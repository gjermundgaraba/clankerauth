import { Clock, Effect, Schema } from "effect";
import { NotFound } from "@clankerauth/admin-api";
import type { Kysely } from "kysely";
import { persisted, transaction, type DatabaseSchema, type Sql } from "./database.ts";
import { clearCodes, clearGrants, referencePrefix } from "./grants.ts";
import { protocolScopes } from "./resources.ts";

const decodeConnections = persisted(
  Schema.Array(
    Schema.Struct({
      client_id: Schema.String,
      resource: Schema.String,
      scopes: Schema.fromJsonString(Schema.Array(Schema.String)),
      approvedAt: Schema.NullOr(Schema.DateTimeUtcFromString),
      refreshedAt: Schema.NullOr(Schema.DateTimeUtcFromString),
    }),
  ),
);

/** Owner policy over provider client rows: blocking uses the provider's own `disabled`
 * flag, which it enforces at authorize, token and refresh.
 */
export function clientStore(database: Kysely<DatabaseSchema>, sql: Sql) {
  const exists = Effect.fn("Clients.exists")(function* (clientId: string, query: Sql) {
    if (!(yield* query`SELECT 1 FROM oauthClient WHERE clientId = ${clientId}`).length)
      return yield* Effect.fail(new NotFound({ error: "Client not found" }));
  });

  const revoke = Effect.fn("Clients.revoke")(function* (
    clientId: string,
    resource: string | undefined,
    query: Sql,
  ) {
    yield* exists(clientId, query);
    yield* clearGrants(query, { clientId, resource });

    return { revoked: true };
  });

  return {
    /** Without a resource, every authorization the client holds. */
    revoke: (clientId: string, resource?: string) =>
      transaction(database, (query) => revoke(clientId, resource, query)),
    /** Forgets any client, managed or automatic; an automatic one can register again.
     * Its links, consents and tokens cascade with the row. */
    delete: (clientId: string) =>
      transaction(database, (query) =>
        Effect.gen(function* () {
          yield* exists(clientId, query);
          yield* clearCodes(query, clientId, null);
          yield* query`DELETE FROM oauthClient WHERE clientId = ${clientId}`;

          return { deleted: true };
        }),
      ),
    /**
     * What each client holds, per resource: a consent, a live refresh token, or both. A
     * managed client skips consent, so only its refresh tokens show. Scopes are the
     * consent's, else the newest token's; rotation revokes the replaced token.
     */
    connections: Effect.fn("Clients.connections")(function* () {
      const now = new Date(yield* Clock.currentTimeMillis).toISOString();

      const rows = yield* decodeConnections(
        yield* sql`WITH live AS (
            SELECT clientId, referenceId, scopes, createdAt FROM oauthRefreshToken
            WHERE revoked IS NULL AND expiresAt > ${now}
          ), held AS (
            SELECT clientId, referenceId FROM oauthConsent
            UNION SELECT clientId, referenceId FROM live
          )
          SELECT h.clientId AS client_id, r.identifier AS resource, c.updatedAt AS approvedAt,
            COALESCE(c.scopes, (SELECT l.scopes FROM live l WHERE l.clientId = h.clientId
              AND l.referenceId = h.referenceId ORDER BY l.createdAt DESC LIMIT 1)) AS scopes,
            (SELECT MAX(l.createdAt) FROM live l WHERE l.clientId = h.clientId
              AND l.referenceId = h.referenceId) AS refreshedAt
          FROM held h
          JOIN oauthResource r ON h.referenceId = ${referencePrefix} || r.identifier
          LEFT JOIN oauthConsent c ON c.clientId = h.clientId AND c.referenceId = h.referenceId
          ORDER BY client_id, resource`,
      );

      return rows.map((row) => ({
        ...row,
        scopes: row.scopes.filter((scope) => !protocolScopes.includes(scope)),
      }));
    }),
    block: (clientId: string, blocked: boolean) =>
      transaction(database, (query) =>
        Effect.gen(function* () {
          if (blocked) yield* revoke(clientId, undefined, query);
          else yield* exists(clientId, query);
          yield* query`UPDATE oauthClient SET disabled = ${blocked ? 1 : 0}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${clientId}`;

          return { blocked };
        }),
      ),
  };
}
