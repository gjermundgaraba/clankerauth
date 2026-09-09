import { randomUUID } from "node:crypto";
import { Effect, Schema } from "effect";
import type { SqlClient } from "effect/unstable/sql/SqlClient";
import { APIError } from "better-auth/api";
import { ClientAccess, Resource } from "@clankerauth/api";

export const protocolScopes = ["openid", "profile", "email", "offline_access"];
export const resourceReference = (identifier: string) => `resource:${identifier}`;
const decodeScopes = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Array(Schema.String)));
const resourceRow = Schema.decodeUnknownEffect(
  Schema.Struct({ identifier: Schema.String, name: Schema.String, allowedScopes: Schema.String }),
);
const accessRows = Schema.decodeUnknownEffect(Schema.Array(ClientAccess));
const credentialRows = Schema.decodeUnknownEffect(
  Schema.Array(Schema.Struct({ id: Schema.String, scopes: Schema.String })),
);
const codeRows = Schema.decodeUnknownEffect(
  Schema.Array(Schema.Struct({ id: Schema.String, value: Schema.String })),
);
const decodeCode = Schema.decodeUnknownEffect(
  Schema.fromJsonString(
    Schema.Struct({
      type: Schema.Literal("authorization_code"),
      query: Schema.Struct({ client_id: Schema.String, scope: Schema.optional(Schema.String) }),
      referenceId: Schema.String,
    }),
  ),
);
type ResourceValue = typeof Resource.Type;

// Callers admit resource operations through Service.exclusive so provider writes
// cannot interleave with transactions using the same SQLite database.
export function resourceStore(
  sql: SqlClient,
  changed: (scopes: string[], identifiers: string[]) => void,
) {
  const decodeResource = Effect.fn("Resources.decode")(function* (value: unknown) {
    const row = yield* resourceRow(value);
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
      uri.protocol !== "https:" ||
      identifier.includes("#") ||
      identifier.includes("?") ||
      uri.username ||
      uri.password
    )
      throw new APIError("BAD_REQUEST", {
        message: "Resource identifiers must be HTTPS URLs without credentials, query or fragment",
      });
    if (
      !name ||
      !scopes.length ||
      scopes.some((scope) => !/^[a-z][a-z0-9:-]+$/.test(scope) || protocolScopes.includes(scope))
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
  const syncClient = Effect.fn("Resources.syncClient")(function* (clientId: string) {
    const links = yield* accessForClient(clientId);
    const scopes = yield* scopesFor(links.map((link) => link.resource));
    yield* sql`UPDATE oauthClient SET scopes = ${JSON.stringify(scopes)}, updatedAt = ${Date.now()} WHERE clientId = ${clientId}`;
  });
  const cleanup = Effect.fn("Resources.cleanup")(function* (
    clientId: string,
    identifier: string,
    removed?: readonly string[],
  ) {
    const reference = resourceReference(identifier);
    const affected = (scopes: readonly string[]) =>
      !removed || scopes.some((scope) => removed.includes(scope));
    const consents = yield* credentialRows(
      yield* sql`SELECT id, scopes FROM oauthConsent WHERE clientId = ${clientId} AND referenceId = ${reference}`,
    );
    for (const consent of consents) {
      if (!removed) yield* sql`DELETE FROM oauthConsent WHERE id = ${consent.id}`;
      else {
        const scopes = (yield* decodeScopes(consent.scopes)).filter(
          (scope) => !removed.includes(scope),
        );
        yield* sql`UPDATE oauthConsent SET scopes = ${JSON.stringify(scopes)}, updatedAt = ${Date.now()} WHERE id = ${consent.id}`;
      }
    }
    const codes = yield* codeRows(
      yield* sql`SELECT id, value FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.referenceId') = ${reference} AND json_extract(value, '$.query.client_id') = ${clientId}`,
    );
    for (const row of codes) {
      const value = yield* decodeCode(row.value);
      if (affected(value.query.scope?.split(" ") ?? []))
        yield* sql`DELETE FROM verification WHERE id = ${row.id}`;
    }
    // Delete dependents before refresh tokens because refreshId is a foreign key.
    for (const table of ["oauthAccessToken", "oauthRefreshToken"]) {
      const rows = yield* credentialRows(
        yield* sql`SELECT id, scopes FROM ${sql(table)} WHERE clientId = ${clientId} AND referenceId = ${reference}`,
      );
      for (const row of rows)
        if (affected(yield* decodeScopes(row.scopes))) {
          if (table === "oauthRefreshToken")
            yield* sql`DELETE FROM oauthAccessToken WHERE refreshId = ${row.id}`;
          yield* sql`DELETE FROM ${sql(table)} WHERE id = ${row.id}`;
        }
    }
  });
  const publish = (catalog: ResourceValue[]) =>
    changed(
      [...new Set([...protocolScopes, ...catalog.flatMap((resource) => resource.scopes)])],
      catalog.map((resource) => resource.identifier),
    );
  const commit = <A, E, R>(operation: Effect.Effect<A, E, R>) =>
    Effect.gen(function* () {
      const committed = yield* sql.withTransaction(
        Effect.gen(function* () {
          const result = yield* operation;
          return { result, catalog: yield* list() };
        }),
      );
      publish(committed.catalog);
      return committed.result;
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
    synchronize: Effect.fn("Resources.synchronize")(function* () {
      publish(yield* list());
    }),
    create: Effect.fn("Resources.create")(function* (input: ResourceValue) {
      const resource = yield* validateInput(input);
      return yield* commit(
        Effect.gen(function* () {
          if (yield* get(resource.identifier))
            return yield* Effect.fail(
              new APIError("CONFLICT", { message: "Resource already exists" }),
            );
          const now = Date.now();
          yield* sql`INSERT INTO oauthResource (id, identifier, name, allowedScopes, accessTokenTtl, createdAt, updatedAt) VALUES (${randomUUID()}, ${resource.identifier}, ${resource.name}, ${JSON.stringify([...protocolScopes, ...resource.scopes])}, 300, ${now}, ${now})`;
          for (const client of yield* Schema.decodeUnknownEffect(
            Schema.Array(Schema.Struct({ clientId: Schema.String })),
          )(
            yield* sql`SELECT clientId FROM clientOnboarding WHERE clientId IN (SELECT clientId FROM oauthClient)`,
          )) {
            yield* sql`INSERT OR IGNORE INTO oauthClientResource (id, clientId, resourceId, createdAt) VALUES (${randomUUID()}, ${client.clientId}, ${resource.identifier}, ${now})`;
            yield* syncClient(client.clientId);
          }
          return resource;
        }),
      );
    }),
    update: Effect.fn("Resources.update")(function* (input: ResourceValue) {
      const resource = yield* validateInput(input);
      return yield* commit(
        Effect.gen(function* () {
          const previous = yield* get(resource.identifier);
          if (!previous)
            return yield* Effect.fail(new APIError("NOT_FOUND", { message: "Resource not found" }));
          yield* sql`UPDATE oauthResource SET name = ${resource.name}, allowedScopes = ${JSON.stringify([...protocolScopes, ...resource.scopes])}, updatedAt = ${Date.now()}, policyVersion = COALESCE(policyVersion, 1) + 1 WHERE identifier = ${resource.identifier}`;
          const removed = previous.scopes.filter((scope) => !resource.scopes.includes(scope));
          for (const link of yield* accessForResource(resource.identifier)) {
            yield* syncClient(link.client_id);
            if (removed.length) yield* cleanup(link.client_id, resource.identifier, removed);
          }
          return resource;
        }),
      );
    }),
    delete: Effect.fn("Resources.delete")(function* (identifier: string) {
      return yield* commit(
        Effect.gen(function* () {
          if (!(yield* get(identifier)))
            return yield* Effect.fail(new APIError("NOT_FOUND", { message: "Resource not found" }));
          const links =
            yield* sql`SELECT 1 FROM oauthClientResource WHERE resourceId = ${identifier} AND clientId NOT IN (SELECT clientId FROM clientOnboarding) LIMIT 1`;
          if (links.length)
            return yield* Effect.fail(
              new APIError("CONFLICT", {
                message: "Remove Client access before deleting this Resource",
              }),
            );
          for (const link of yield* accessForResource(identifier)) {
            yield* cleanup(link.client_id, identifier);
            yield* sql`DELETE FROM oauthClientResource WHERE clientId = ${link.client_id} AND resourceId = ${identifier}`;
            yield* syncClient(link.client_id);
          }
          yield* sql`DELETE FROM oauthResource WHERE identifier = ${identifier}`;
          return { deleted: true };
        }),
      );
    }),
    setAccess: Effect.fn("Resources.setAccess")(function* (
      clientId: string,
      identifiers: readonly string[],
    ) {
      return yield* commit(
        Effect.gen(function* () {
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
          for (const identifier of previous.filter((id) => !identifiers.includes(id))) {
            yield* cleanup(clientId, identifier);
            yield* sql`DELETE FROM oauthClientResource WHERE clientId = ${clientId} AND resourceId = ${identifier}`;
          }
          for (const identifier of identifiers.filter((id) => !previous.includes(id)))
            yield* sql`INSERT INTO oauthClientResource (id, clientId, resourceId, createdAt) VALUES (${randomUUID()}, ${clientId}, ${identifier}, ${Date.now()})`;
          yield* syncClient(clientId);
          return yield* accessForClient(clientId);
        }),
      );
    }),
  };
}
