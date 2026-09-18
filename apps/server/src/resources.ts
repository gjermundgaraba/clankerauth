import { randomUUID } from "node:crypto";
import { Effect, Schema } from "effect";
import { normalizeError, type Sql } from "./database.ts";
import { APIError } from "better-auth/api";
import type { Auth } from "better-auth";
import type { oauthProvider } from "@better-auth/oauth-provider";
import { ClientAccess, Resource } from "@clankerauth/api";

export const mcpScope = "admin";

export const mcpResource = (baseURL: string) => `${baseURL}/mcp`;

export const protocolScopes = ["openid", "profile", "email", "offline_access"];

export const resourceReference = (identifier: string) => `resource:${identifier}`;

const decodeScopes = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Array(Schema.String)));

const ResourceRow = Schema.Struct({
  identifier: Schema.String,
  name: Schema.String,
  allowedScopes: Schema.String,
});

const decodeResourceRow = Schema.decodeUnknownEffect(ResourceRow);

const accessRows = Schema.decodeUnknownEffect(Schema.Array(ClientAccess));

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
  Effect.tryPromise({
    try: operation,
    catch: normalizeError,
  });

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

  const validate = (input: ResourceValue): ResourceValue => {
    const identifier = input.identifier.trim();
    const name = input.name.trim();
    const scopes = [...new Set(input.scopes.map((scope) => scope.trim()))];
    let uri: URL;

    try {
      uri = new URL(identifier);
    } catch {
      throw new APIError("BAD_REQUEST", { message: "Invalid Resource identifier" });
    }

    if (
      !["http:", "https:"].includes(uri.protocol) ||
      identifier.includes("#") ||
      identifier.includes("?") ||
      uri.username ||
      uri.password
    )
      throw new APIError("BAD_REQUEST", {
        message:
          "Resource identifiers must be HTTP or HTTPS URLs without credentials, query or fragment",
      });

    if (
      !name ||
      !scopes.length ||
      scopes.some(
        (scope) => !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope) || protocolScopes.includes(scope),
      )
    )
      throw new APIError("BAD_REQUEST", {
        message: "Resources require a name and nonempty custom scopes",
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
      yield* sql`UPDATE oauthClient SET scopes = ${JSON.stringify(scopes)}, updatedAt = ${Date.now()} WHERE clientId = ${clientId}`;
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

  const initialize = Effect.fn("Resources.initialize")(function* () {
    // This resource is application policy, present even before owner setup.
    const now = Date.now();
    yield* sql`INSERT OR IGNORE INTO oauthResource
      (id, identifier, name, allowedScopes, accessTokenTtl, disabled, createdAt, updatedAt, policyVersion)
      VALUES (${randomUUID()}, ${reservedIdentifier}, 'Clanker Auth administration', ${JSON.stringify([...protocolScopes, mcpScope])}, 300, 0, ${now}, ${now}, 1)`;
    publish(yield* list());
  });

  return {
    list,
    get,
    initialize,
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

      if (yield* get(resource.identifier))
        return yield* Effect.fail(new APIError("CONFLICT", { message: "Resource already exists" }));
      yield* providerCall(() =>
        getAuth().api.adminCreateOAuthResource({
          headers,
          body: {
            identifier: resource.identifier,
            name: resource.name,
            allowedScopes: [...protocolScopes, ...resource.scopes],
            accessTokenTtl: 300,
          },
        }),
      );
      // Publish before updating client scopes: the provider validates that union
      // against its currently supported scopes. Keep defaults current after writes.
      yield* synchronize();

      const clients = yield* Schema.decodeUnknownEffect(
        Schema.Array(Schema.Struct({ clientId: Schema.String })),
      )(
        yield* sql`SELECT clientId FROM clientOnboarding WHERE clientId IN (SELECT clientId FROM oauthClient)`,
      );

      for (const client of clients) {
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

      if ((yield* sql`SELECT 1 FROM clientOnboarding WHERE clientId = ${clientId}`).length)
        return yield* Effect.fail(
          new APIError("BAD_REQUEST", {
            message: "Automatically onboarded Clients use owner consent for Resource access",
          }),
        );
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
