import { Clock, Effect, Schema } from "effect";
import { normalizeError, type Sql } from "./database.ts";
import { APIError } from "better-auth/api";
import type { Auth } from "better-auth";
import type { oauthProvider } from "@better-auth/oauth-provider";
import { ClientAccess, Resource } from "@clankerauth/admin-api";

export const mcpScope = "admin";

export const mcpResource = (baseURL: string) => `${baseURL}/mcp`;

/** Reserved scope names that resources cannot define; the only protocol scope is refresh. */
export const protocolScopes = ["offline_access"];

export const resourceReference = (identifier: string) => `resource:${identifier}`;

const decodeScopes = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Array(Schema.String)));

const ResourceRow = Schema.Struct({
  identifier: Schema.String,
  name: Schema.String,
  allowedScopes: Schema.String,
});

const decodeResourceRow = Schema.decodeUnknownEffect(ResourceRow);

const accessRows = Schema.decodeUnknownEffect(Schema.Array(ClientAccess));

const clientIds = Schema.decodeUnknownEffect(
  Schema.Array(Schema.Struct({ clientId: Schema.String })),
);

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

const providerCall = <A>(operation: () => Promise<A>) =>
  Effect.tryPromise({ try: operation, catch: normalizeError });

const resourceParams = (identifier: string) => ({
  identifier: encodeURIComponent(identifier),
});

const linkParams = (clientId: string, identifier: string) => ({
  ...resourceParams(identifier),
  client_id: encodeURIComponent(clientId),
});

// Provider APIs own their writes and transaction boundaries.
// Do not hold a separate transaction while calling them on the shared connection.
export function resourceStore(
  sql: Sql,
  getAuth: () => ResourceAuth,
  changed: (scopes: string[], identifiers: string[]) => void,
  reservedIdentifier: string,
) {
  // eslint-disable-next-line anti-slop/no-unknown-parameters -- Persisted-row boundary: validate fields before use.
  const decodeResource = Effect.fn("Resources.decode")(function* (value: unknown) {
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

  const accessForResource = Effect.fn("Resources.accessForResource")(function* (
    identifier: string,
  ) {
    return yield* accessRows(
      yield* sql`SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource WHERE resourceId = ${identifier} ORDER BY clientId`,
    );
  });

  const validateSelection = Effect.fn("Resources.validateSelection")(function* (
    identifiers: readonly string[],
  ) {
    if (new Set(identifiers).size !== identifiers.length)
      return yield* Effect.fail(
        new APIError("BAD_REQUEST", { message: "Choose unique Resources" }),
      );

    return yield* Effect.forEach(identifiers, (id) =>
      Effect.gen(function* () {
        const resource = yield* get(id);

        if (!resource)
          return yield* Effect.fail(new APIError("BAD_REQUEST", { message: "Unknown Resource" }));

        return resource;
      }),
    );
  });

  const scopesFor = Effect.fn("Resources.scopesFor")(function* (identifiers: readonly string[]) {
    const resources = yield* validateSelection(identifiers);

    return [...new Set([...protocolScopes, ...resources.flatMap((resource) => resource.scopes)])];
  });

  // The provider validates identifiers (RFC 8707) and rejects duplicates.
  const validate = (input: ResourceValue): ResourceValue => {
    const identifier = input.identifier.trim();
    const name = input.name.trim();
    const scopes = [...new Set(input.scopes.map((scope) => scope.trim()))];

    if (
      !name ||
      scopes.some(
        (scope) => !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope) || protocolScopes.includes(scope),
      )
    )
      throw new APIError("BAD_REQUEST", {
        message: "Resources require a name and well-formed custom scopes",
      });

    return { identifier, name, scopes };
  };

  const validateInput = (input: ResourceValue) =>
    Effect.try({
      try: () => validate(input),
      catch: (error) =>
        error instanceof APIError
          ? error
          : new APIError("BAD_REQUEST", { message: "Invalid Resource" }),
    });

  const syncClient = Effect.fn("Resources.syncClient")(function* (
    clientId: string,
    headers: Headers,
  ) {
    const links = yield* accessForClient(clientId);
    const scopes = yield* scopesFor(links.map((link) => link.resource));

    const unownedClient =
      yield* sql`SELECT 1 FROM oauthClient WHERE clientId = ${clientId} AND userId IS NULL`;

    if (unownedClient.length) {
      // Provider update APIs require ownership even for admins. Unowned clients
      // need direct persistence of their scope union.
      yield* sql`UPDATE oauthClient SET scopes = ${JSON.stringify(scopes)}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${clientId}`;
    } else {
      yield* providerCall(() =>
        getAuth().api.updateOAuthClient({
          headers,
          body: { client_id: clientId, update: { scope: scopes.join(" ") } },
        }),
      );
    }
  });

  const publish = (catalog: ResourceValue[]) =>
    changed(
      [...new Set([...protocolScopes, ...catalog.flatMap((resource) => resource.scopes)])],
      catalog.map((resource) => resource.identifier),
    );

  const synchronize = Effect.fn("Resources.synchronize")(function* () {
    publish(yield* list());
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
      yield* providerCall(() =>
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

      for (const client of automatic) {
        yield* providerCall(() =>
          getAuth().api.adminLinkClientResource({
            headers,
            params: linkParams(client.clientId, resource.identifier),
          }),
        );
        yield* syncClient(client.clientId, headers);
      }

      return resource;
    }),
    update: Effect.fn("Resources.update")(function* (input: ResourceValue, headers: Headers) {
      const resource = yield* validateInput(input);
      const builtIn = resource.identifier === reservedIdentifier;

      if (builtIn && (resource.scopes.length !== 1 || resource.scopes[0] !== mcpScope))
        return yield* Effect.fail(
          new APIError("BAD_REQUEST", {
            message: "The administration Resource scopes are reserved",
          }),
        );
      yield* providerCall(() =>
        getAuth().api.adminUpdateOAuthResource({
          headers,
          params: resourceParams(resource.identifier),
          body: builtIn
            ? { name: resource.name }
            : { name: resource.name, allowedScopes: [...protocolScopes, ...resource.scopes] },
        }),
      );

      if (builtIn) return resource;
      yield* synchronize();

      for (const link of yield* accessForResource(resource.identifier))
        yield* syncClient(link.client_id, headers);

      return resource;
    }),
    delete: Effect.fn("Resources.delete")(function* (identifier: string, headers: Headers) {
      if (identifier === reservedIdentifier)
        return yield* Effect.fail(
          new APIError("BAD_REQUEST", { message: "The administration Resource is reserved" }),
        );
      const links = yield* accessForResource(identifier);
      yield* providerCall(() =>
        getAuth().api.adminDeleteOAuthResource({
          headers,
          params: resourceParams(identifier),
        }),
      );
      // The provider removes the resource and foreign keys remove its links.
      // Existing grants retain provider semantics; current resource policy controls eligibility.
      yield* synchronize();

      for (const link of links) yield* syncClient(link.client_id, headers);

      return { deleted: true };
    }),
    setAccess: Effect.fn("Resources.setAccess")(function* (
      clientId: string,
      identifiers: readonly string[],
      headers: Headers,
    ) {
      const clients = yield* sql`SELECT id FROM oauthClient WHERE clientId = ${clientId}`;

      if (!clients.length)
        return yield* Effect.fail(new APIError("NOT_FOUND", { message: "Client not found" }));
      yield* validateSelection(identifiers);
      const previous = (yield* accessForClient(clientId)).map((link) => link.resource);

      for (const identifier of previous.filter((id) => !identifiers.includes(id)))
        yield* providerCall(() =>
          getAuth().api.adminUnlinkClientResource({
            headers,
            params: linkParams(clientId, identifier),
          }),
        );

      for (const identifier of identifiers.filter((id) => !previous.includes(id)))
        yield* providerCall(() =>
          getAuth().api.adminLinkClientResource({
            headers,
            params: linkParams(clientId, identifier),
          }),
        );
      yield* syncClient(clientId, headers);

      return yield* accessForClient(clientId);
    }),
  };
}
