import { randomUUID } from "node:crypto";
import { Clock, Effect, Schema, Semaphore } from "effect";
import type { Kysely } from "kysely";
import {
  persisted,
  transaction,
  type DatabaseSchema,
  type Sql,
  type SqliteRow,
} from "./database.ts";
import type { Auth } from "better-auth";
import type { oauthProvider } from "@better-auth/oauth-provider";
import { BadRequest, ClientAccess, NotFound, Resource } from "@clankerauth/admin-api";
import { invalidInput, provider } from "./api-errors.ts";
import { clearGrants } from "./grants.ts";

/** The administration resource's fixed scopes: `read` allows listing, and `write` allows
 * everything. */
export const administrationScopes = { read: "clankerauth:read", write: "clankerauth:write" };

/**
 * The issuer's own resource: its origin root, as every application's is. It names the
 * token audience of administration, over `/mcp` and `/api/owner/<action>` alike; the
 * dashboard at `/` takes the owner's session cookie, never a token.
 */
export const administrationIdentifier = (baseURL: string) => new URL("/", baseURL).href;

/** What the administration resource was named before 0.16.0. */
export const legacyAdministrationIdentifier = (baseURL: string) => `${baseURL}/mcp`;

/** Reserved scope names that resources cannot define; the only protocol scope is refresh. */
export const protocolScopes = ["offline_access"];

const decodeScopes = persisted(Schema.fromJsonString(Schema.Array(Schema.String)));

const ResourceRow = Schema.Struct({
  identifier: Schema.String,
  name: Schema.String,
  allowedScopes: Schema.String,
});

const decodeResourceRow = persisted(ResourceRow);

const accessRows = persisted(Schema.Array(ClientAccess));

const clientIds = persisted(Schema.Array(Schema.Struct({ clientId: Schema.String })));

const clientOwners = persisted(
  Schema.Array(Schema.Struct({ userId: Schema.NullOr(Schema.String) })),
);

type ResourceValue = typeof Resource.Type;

type ResourceAuth = {
  api: Pick<
    Auth<{ plugins: [ReturnType<typeof oauthProvider>] }>["api"],
    "adminCreateOAuthResource" | "adminUpdateOAuthResource" | "adminDeleteOAuthResource"
  >;
};

const resourceParams = (identifier: string) => ({
  identifier: encodeURIComponent(identifier),
});

// Provider APIs own their writes and transaction boundaries. Do not hold a separate
// transaction while calling them on the shared connection. Mutations take one permit,
// so their read-diff-write sequences never interleave.
//
// Client access applies to managed clients only: they skip consent, so their links are
// the whole of what they may obtain. An automatic client may ask for any resource, and
// consent decides; the provider's own per-client enforcement is off, so its links are
// neither written nor read.
export const resourceStore = Effect.fnUntraced(function* (
  database: Kysely<DatabaseSchema>,
  sql: Sql,
  getAuth: () => ResourceAuth,
  changed: (scopes: string[]) => void,
  reservedIdentifier: string,
) {
  const mutating = yield* Semaphore.make(1);
  const serialized = <A, E, R>(effect: Effect.Effect<A, E, R>) => mutating.withPermit(effect);

  const decodeResource = Effect.fn("Resources.decode")(function* (value: SqliteRow) {
    const row = yield* decodeResourceRow(value);
    const scopes = yield* decodeScopes(row.allowedScopes);

    return {
      identifier: row.identifier,
      name: row.name,
      scopes: scopes.filter((scope) => !protocolScopes.includes(scope)),
    };
  });

  const list = Effect.fn("Resources.list")(function* () {
    const rows =
      yield* sql`SELECT identifier, name, allowedScopes FROM oauthResource ORDER BY createdAt, identifier`;

    return yield* Effect.forEach(rows, decodeResource);
  });

  const get = Effect.fn("Resources.get")(function* (identifier: string) {
    const rows =
      yield* sql`SELECT identifier, name, allowedScopes FROM oauthResource WHERE identifier = ${identifier}`;

    return rows[0] ? yield* decodeResource(rows[0]) : undefined;
  });

  // Only managed clients have links; nothing writes them for automatic ones.
  const access = Effect.fn("Resources.access")(function* () {
    return yield* accessRows(
      yield* sql`SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource ORDER BY clientId, resourceId`,
    );
  });

  const accessForClient = Effect.fn("Resources.accessForClient")(function* (
    clientId: string,
    query: Sql,
  ) {
    return yield* accessRows(
      yield* query`SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource WHERE clientId = ${clientId} ORDER BY resourceId`,
    );
  });

  const scopesOf = (catalog: readonly ResourceValue[], identifiers: readonly string[]) => [
    ...new Set([
      ...protocolScopes,
      ...identifiers.flatMap(
        (id) => catalog.find((resource) => resource.identifier === id)?.scopes ?? [],
      ),
    ]),
  ];

  const validateSelection = Effect.fn("Resources.validateSelection")(function* (
    catalog: readonly ResourceValue[],
    identifiers: readonly string[],
  ) {
    const unknown = identifiers.findIndex(
      (id) => !catalog.some((resource) => resource.identifier === id),
    );

    if (unknown !== -1) return yield* invalidInput(["resources", unknown], "Unknown Resource");
  });

  const scopesFor = Effect.fn("Resources.scopesFor")(function* (identifiers: readonly string[]) {
    const catalog = yield* list();
    yield* validateSelection(catalog, identifiers);

    return scopesOf(catalog, identifiers);
  });

  // An identifier must already be the string a client sends back. A client asks for
  // `new URL(metadata.resource).href`, and the access token's audience is that string,
  // so `https://notes.example` (no slash) would be rewritten and stop matching what is
  // registered here. Refuse it rather than let a resource server fail at verification.
  // RFC 8707 forbids a fragment; in canonical form a `#` can only begin one.
  const canonical = (identifier: string) => {
    try {
      return new URL(identifier).href === identifier && !identifier.includes("#");
    } catch {
      return false;
    }
  };

  // The provider validates identifiers (RFC 8707) and rejects duplicates. The contract's
  // schema checks the name and each scope's form.
  const validateInput = Effect.fn("Resources.validateInput")(function* (input: ResourceValue) {
    const identifier = input.identifier.trim();
    const name = input.name.trim();
    const scopes = [...new Set(input.scopes.map((scope) => scope.trim()))];

    if (!canonical(identifier))
      return yield* invalidInput(
        ["identifier"],
        "Resource identifiers must be absolute URIs in canonical form, without a fragment",
      );

    // A protocol scope is the provider's, which no resource may declare: name it as sent.
    const reserved = input.scopes.findIndex((scope) => protocolScopes.includes(scope.trim()));

    if (reserved !== -1)
      return yield* invalidInput(["scopes", reserved], "offline_access is reserved");

    return { identifier, name, scopes } satisfies ResourceValue;
  });

  // A client's scope ceiling is a copy the provider reads on every request: the whole
  // catalog for an automatic client, which the provider itself writes at registration
  // and on every CIMD refresh, and the union of its resources' scopes for a managed one.
  // Copies are written directly, so they can be rebuilt without an owner session, and only
  // when they change.
  const syncClient = Effect.fn("Resources.syncClient")(function* (
    query: Sql,
    catalog: readonly ResourceValue[],
    clientId: string,
  ) {
    const links = yield* accessForClient(clientId, query);

    const scopes = JSON.stringify(
      scopesOf(
        catalog,
        links.map((link) => link.resource),
      ),
    );

    yield* query`UPDATE oauthClient SET scopes = ${scopes}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${clientId} AND scopes IS NOT ${scopes}`;
  });

  // Publishes the catalog and rebuilds every client's copy of it. A resource change and
  // its client copies are separate writes, so a failure between them heals here.
  const synchronize = Effect.fn("Resources.synchronize")(function* () {
    const catalog = yield* list();

    const scopes = scopesOf(
      catalog,
      catalog.map((resource) => resource.identifier),
    );

    changed(scopes);
    yield* sql`UPDATE oauthClient SET scopes = ${JSON.stringify(scopes)}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE userId IS NULL AND scopes IS NOT ${JSON.stringify(scopes)}`;

    for (const client of yield* clientIds(
      yield* sql`SELECT clientId FROM oauthClient WHERE userId IS NOT NULL ORDER BY clientId`,
    ))
      yield* syncClient(sql, catalog, client.clientId);
  });

  // The caller named it: input this issuer decodes but will not serve.
  const reserved = (identifier: string) =>
    identifier === reservedIdentifier
      ? Effect.fail(invalidInput(["identifier"], "The administration Resource is fixed"))
      : Effect.void;

  return {
    list,
    get,
    access,
    /** An automatic client may ask for any resource; a managed one only for its own. */
    hasAccess: Effect.fn("Resources.hasAccess")(function* (clientId: string, identifier: string) {
      const rows =
        yield* sql`SELECT 1 FROM oauthClient c WHERE c.clientId = ${clientId} AND (c.userId IS NULL
        OR EXISTS (SELECT 1 FROM oauthClientResource l WHERE l.clientId = c.clientId AND l.resourceId = ${identifier}))`;

      return rows.length > 0;
    }),
    scopesFor,
    synchronize,
    create: Effect.fn("Resources.create")(function* (input: ResourceValue, headers: Headers) {
      const resource = yield* validateInput(input);

      // Recreating a resource revives nothing, even if its deletion never cleared its grants.
      // Nothing is granted for an unknown resource, so none can appear before it exists.
      if (!(yield* get(resource.identifier)))
        yield* transaction(database, (query) =>
          clearGrants(query, { resource: resource.identifier }),
        );
      yield* provider(() =>
        getAuth().api.adminCreateOAuthResource({
          headers,
          body: {
            identifier: resource.identifier,
            name: resource.name,
            allowedScopes: [...protocolScopes, ...resource.scopes],
          },
        }),
      );
      yield* synchronize();

      return resource;
    }, serialized),
    update: Effect.fn("Resources.update")(function* (input: ResourceValue, headers: Headers) {
      const resource = yield* validateInput(input);
      yield* reserved(resource.identifier);
      yield* provider(() =>
        getAuth().api.adminUpdateOAuthResource({
          headers,
          params: resourceParams(resource.identifier),
          body: { name: resource.name, allowedScopes: [...protocolScopes, ...resource.scopes] },
        }),
      );
      yield* synchronize();

      return resource;
    }, serialized),
    delete: Effect.fn("Resources.delete")(function* (identifier: string, headers: Headers) {
      yield* reserved(identifier);
      yield* provider(() =>
        getAuth().api.adminDeleteOAuthResource({
          headers,
          params: resourceParams(identifier),
        }),
      );
      // The provider removes the resource and foreign keys remove its links; the
      // authorization clients were given for it goes with it. Should this clear fail,
      // create clears it before the identifier can be used again.
      yield* transaction(database, (query) => clearGrants(query, { resource: identifier }));
      yield* synchronize();

      return { deleted: true };
    }, serialized),
    // Links and the authorization they allowed change in one local transaction, so
    // restoring access asks again rather than reviving a grant that removal missed.
    setAccess: Effect.fn("Resources.setAccess")(function* (
      clientId: string,
      identifiers: readonly string[],
    ) {
      const [client] = yield* clientOwners(
        yield* sql`SELECT userId FROM oauthClient WHERE clientId = ${clientId}`,
      );

      if (!client) return yield* Effect.fail(new NotFound({ error: "Client not found" }));

      if (client.userId === null)
        return yield* Effect.fail(
          new BadRequest({
            error: "Automatic Clients may ask for any Resource; revoke or block them instead",
          }),
        );
      const catalog = yield* list();
      yield* validateSelection(catalog, identifiers);
      const now = yield* Clock.currentTimeMillis;

      yield* transaction(database, (query) =>
        Effect.gen(function* () {
          const previous = (yield* accessForClient(clientId, query)).map((link) => link.resource);

          for (const identifier of previous.filter((id) => !identifiers.includes(id))) {
            yield* query`DELETE FROM oauthClientResource WHERE clientId = ${clientId} AND resourceId = ${identifier}`;
            yield* clearGrants(query, { clientId, resource: identifier });
          }

          for (const identifier of identifiers)
            yield* query`INSERT OR IGNORE INTO oauthClientResource (id, clientId, resourceId, createdAt)
              VALUES (${randomUUID()}, ${clientId}, ${identifier}, ${new Date(now).toISOString()})`;
          yield* syncClient(query, catalog, clientId);
        }),
      );

      return yield* accessForClient(clientId, sql);
    }, serialized),
  };
});
