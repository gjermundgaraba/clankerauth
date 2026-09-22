import { Clock, Effect } from "effect";
import { NotFound } from "@clankerauth/admin-api";
import type { Kysely } from "kysely";
import { transaction, type DatabaseSchema, type Sql } from "./database.ts";

/** Owner policy over provider client rows: blocking uses the provider's own `disabled`
 * flag, which it enforces at authorize, token and refresh. The provider has no bulk
 * revocation API, so clearing a client's stored authorization stays local SQL.
 */
export function clientStore(database: Kysely<DatabaseSchema>) {
  const revoke = Effect.fn("Clients.revoke")(function* (clientId: string, query: Sql) {
    if (!(yield* query`SELECT 1 FROM oauthClient WHERE clientId = ${clientId}`).length)
      return yield* Effect.fail(new NotFound({ error: "Client not found" }));
    yield* query`DELETE FROM oauthConsent WHERE clientId = ${clientId}`;
    yield* query`DELETE FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.query.client_id') = ${clientId}`;
    yield* query`DELETE FROM oauthAccessToken WHERE clientId = ${clientId}`;
    yield* query`DELETE FROM oauthRefreshToken WHERE clientId = ${clientId}`;

    return { revoked: true };
  });

  return {
    revoke: (clientId: string) => transaction(database, (query) => revoke(clientId, query)),
    block: (clientId: string, blocked: boolean) =>
      transaction(database, (query) =>
        Effect.gen(function* () {
          if (blocked) yield* revoke(clientId, query);
          else if (!(yield* query`SELECT 1 FROM oauthClient WHERE clientId = ${clientId}`).length)
            return yield* Effect.fail(new NotFound({ error: "Client not found" }));
          yield* query`UPDATE oauthClient SET disabled = ${blocked ? 1 : 0}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${clientId}`;

          return { blocked };
        }),
      ),
  };
}
