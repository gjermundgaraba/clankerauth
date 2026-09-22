import { Clock, Effect, Schema, Semaphore } from "effect";
import { persisted, type Sql, type SqliteRow } from "./database.ts";
import type { Auth } from "better-auth";
import type { oauthProvider } from "@better-auth/oauth-provider";
import { BadRequest, ClientAccess, NotFound, Resource } from "@clankerauth/admin-api";
import { provider } from "./api-errors.ts";

export const mcpScope = "admin";

export const mcpResource = (baseURL: string) => `${baseURL}/mcp`;

/** Reserved scope names that resources cannot define; the only protocol scope is refresh. */
export const protocolScopes = ["offline_access"];

export const resourceReference = (identifier: string) => `resource:${identifier}`;

const decodeScopes = persisted(Schema.fromJsonString(Schema.Array(Schema.String)));

const ResourceRow = Schema.Struct({
  identifier: Schema.String,
  name: Schema.String,
  allowedScopes: Schema.String,
});

const decodeResourceRow = persisted(ResourceRow);

const accessRows = persisted(Schema.Array(ClientAccess));

const clientIds = persisted(Schema.Array(Schema.Struct({ clientId: Schema.String })));

type ResourceValue = typeof Resource.Type;

type ResourceAuth = {
  api: Pick<
    Auth<{ plugins: [ReturnType<typeof oauthProvider>] }>["api"],
    | "adminCreateOAuthResource"
    | "adminUpdateOAuthResource"
    | "adminDeleteOAuthResource"
    | "adminLinkClientResource"
    | "adminUnlinkClientResource"
    | "updateOAuthClient"
  >;
};

const resourceParams = (identifier: string) => ({
  identifier: encodeURIComponent(identifier),
});

const linkParams = (clientId: string, identifier: string) => ({
  ...resourceParams(identifier),
  client_id: encodeURIComponent(clientId),
});

// Provider APIs own their writes and transaction boundaries. Do not hold a separate
// transaction while calling them on the shared connection. Mutations take one permit,
// so their read-diff-write sequences never interleave.
export const resourceStore = Effect.fnUntraced(function* (
  sql: Sql,
  getAuth: () => ResourceAuth,
  changed: (scopes: string[], identifiers: string[]) => void,
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

  const access = Effect.fn("Resources.access")(function* () {
    return yield* accessRows(
      yield* sql`SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource ORDER BY clientId, resourceId`,
    );
  });

  const accessForClient = Effect.fn("Resources.accessForClient")(function* (clientId: string) {
    return yield* accessRows(
      yield* sql`SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource WHERE clientId = ${clientId} ORDER BY resourceId`,
    );
  });

  const validateSelection = Effect.fn("Resources.validateSelection")(function* (
    identifiers: readonly string[],
  ) {
    if (new Set(identifiers).size !== identifiers.length)
      return yield* Effect.fail(new BadRequest({ error: "Choose unique Resources" }));

    return yield* Effect.forEach(identifiers, (id) =>
      Effect.gen(function* () {
        const resource = yield* get(id);

        if (!resource) return yield* Effect.fail(new BadRequest({ error: "Unknown Resource" }));

        return resource;
      }),
    );
  });

  const scopesFor = Effect.fn("Resources.scopesFor")(function* (identifiers: readonly string[]) {
    const resources = yield* validateSelection(identifiers);

    return [...new Set([...protocolScopes, ...resources.flatMap((resource) => resource.scopes)])];
  });

  // An identifier must already be the string a client sends back. A client asks for
  // `new URL(metadata.resource).href`, and the access token's audience is that string,
  // so `https://notes.example` (no slash) would be rewritten and stop matching what is
  // registered here. Refuse it rather than let a resource server fail at verification.
  const canonical = (identifier: string) => {
    try {
      return new URL(identifier).href === identifier;
    } catch {
      return false;
    }
  };

  // The provider validates identifiers (RFC 8707) and rejects duplicates.
  const validateInput = Effect.fn("Resources.validateInput")(function* (input: ResourceValue) {
    const identifier = input.identifier.trim();
    const name = input.name.trim();
    const scopes = [...new Set(input.scopes.map((scope) => scope.trim()))];

    if (!canonical(identifier))
      return yield* Effect.fail(
        new BadRequest({ error: "Resource identifiers must be absolute URIs in canonical form" }),
      );

    if (
      !name ||
      scopes.some(
        (scope) => !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope) || protocolScopes.includes(scope),
      )
    )
      return yield* Effect.fail(
        new BadRequest({ error: "Resources require a name and well-formed custom scopes" }),
      );

    return { identifier, name, scopes } satisfies ResourceValue;
  });

  // A client's scope ceiling is the union of its resources' scopes, kept as a copy the
  // provider reads on every request. It is written directly: the provider's update API
  // demands ownership, and this way the copy can be rebuilt without an owner session.
  const syncClient = Effect.fn("Resources.syncClient")(function* (clientId: string) {
    const links = yield* accessForClient(clientId);
    const scopes = yield* scopesFor(links.map((link) => link.resource));
    yield* sql`UPDATE oauthClient SET scopes = ${JSON.stringify(scopes)}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${clientId}`;
  });

  const publish = (catalog: ResourceValue[]) =>
    changed(
      [...new Set([...protocolScopes, ...catalog.flatMap((resource) => resource.scopes)])],
      catalog.map((resource) => resource.identifier),
    );

  // Publishes the catalog and rebuilds every client's copy of it. A resource change and
  // its client copies are separate writes, so a failure between them heals here.
  const synchronize = Effect.fn("Resources.synchronize")(function* () {
    publish(yield* list());

    for (const client of yield* clientIds(
      yield* sql`SELECT clientId FROM oauthClient ORDER BY clientId`,
    ))
      yield* syncClient(client.clientId);
  });

  return {
    list,
    get,
    access,
    hasAccess: Effect.fn("Resources.hasAccess")(function* (clientId: string, identifier: string) {
      const rows =
        yield* sql`SELECT 1 FROM oauthClientResource WHERE clientId = ${clientId} AND resourceId = ${identifier} LIMIT 1`;

      return rows.length > 0;
    }),
    scopesFor,
    synchronize,
    create: Effect.fn("Resources.create")(function* (input: ResourceValue, headers: Headers) {
      const resource = yield* validateInput(input);
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
      // Publish before updating client scopes: the provider validates that union
      // against its currently supported scopes. Keep defaults current after writes.
      yield* synchronize();

      // Automatically registered clients may request any resource, subject to consent.
      const automatic = yield* clientIds(
        yield* sql`SELECT clientId FROM oauthClient WHERE userId IS NULL ORDER BY clientId`,
      );

      for (const client of automatic)
        yield* provider(() =>
          getAuth().api.adminLinkClientResource({
            headers,
            params: linkParams(client.clientId, resource.identifier),
          }),
        );
      yield* synchronize();

      return resource;
    }, serialized),
    update: Effect.fn("Resources.update")(function* (input: ResourceValue, headers: Headers) {
      const resource = yield* validateInput(input);
      const builtIn = resource.identifier === reservedIdentifier;

      if (builtIn && (resource.scopes.length !== 1 || resource.scopes[0] !== mcpScope))
        return yield* Effect.fail(
          new BadRequest({ error: "The administration Resource scopes are reserved" }),
        );
      yield* provider(() =>
        getAuth().api.adminUpdateOAuthResource({
          headers,
          params: resourceParams(resource.identifier),
          body: builtIn
            ? { name: resource.name }
            : { name: resource.name, allowedScopes: [...protocolScopes, ...resource.scopes] },
        }),
      );

      if (!builtIn) yield* synchronize();

      return resource;
    }, serialized),
    delete: Effect.fn("Resources.delete")(function* (identifier: string, headers: Headers) {
      if (identifier === reservedIdentifier)
        return yield* Effect.fail(
          new BadRequest({ error: "The administration Resource is reserved" }),
        );
      yield* provider(() =>
        getAuth().api.adminDeleteOAuthResource({
          headers,
          params: resourceParams(identifier),
        }),
      );
      // The provider removes the resource and foreign keys remove its links.
      // Existing grants retain provider semantics; current resource policy controls eligibility.
      yield* synchronize();

      return { deleted: true };
    }, serialized),
    setAccess: Effect.fn("Resources.setAccess")(function* (
      clientId: string,
      identifiers: readonly string[],
      headers: Headers,
    ) {
      const clients = yield* sql`SELECT id FROM oauthClient WHERE clientId = ${clientId}`;

      if (!clients.length) return yield* Effect.fail(new NotFound({ error: "Client not found" }));
      yield* validateSelection(identifiers);
      const previous = (yield* accessForClient(clientId)).map((link) => link.resource);

      for (const identifier of previous.filter((id) => !identifiers.includes(id)))
        yield* provider(() =>
          getAuth().api.adminUnlinkClientResource({
            headers,
            params: linkParams(clientId, identifier),
          }),
        );

      for (const identifier of identifiers.filter((id) => !previous.includes(id)))
        yield* provider(() =>
          getAuth().api.adminLinkClientResource({
            headers,
            params: linkParams(clientId, identifier),
          }),
        );
      yield* syncClient(clientId);

      return yield* accessForClient(clientId);
    }, serialized),
  };
});
