import { Clock, Effect, Schema } from "effect";
import { APIError } from "better-auth/api";
import type { Kysely } from "kysely";
// eslint-disable-next-line anti-slop-effect/no-service-constructor-imports -- makeSql adapts this database, not a contextual service.
import { makeSql, transaction, type DatabaseSchema, type Sql } from "./database.ts";

const rows = Schema.decodeUnknownEffect(
  Schema.Array(
    Schema.Struct({
      client_id: Schema.String,
      onboarding: Schema.Literals(["dcr", "cimd"]),
      blocked: Schema.Number,
    }),
  ),
);

// Kept independently from provider metadata so rediscovery cannot erase policy.
export function onboardingStore(database: Kysely<DatabaseSchema>) {
  const sql = makeSql(database);

  const list = Effect.fn("Onboarding.list")(function* () {
    return (yield* rows(
      yield* sql`SELECT clientId AS client_id, source AS onboarding, blocked FROM clientOnboarding`,
    )).map((row) => ({ ...row, blocked: row.blocked !== 0 }));
  });

  const revoke = Effect.fn("Onboarding.revoke")(function* (clientId: string, query: Sql = sql) {
    if (
      !(yield* query`SELECT 1 FROM oauthClient WHERE clientId = ${clientId} UNION SELECT 1 FROM clientOnboarding WHERE clientId = ${clientId}`)
        .length
    )
      return yield* Effect.fail(new APIError("NOT_FOUND", { message: "Client not found" }));
    yield* query`UPDATE oauthClient SET grantGeneration = lower(hex(randomblob(16))) WHERE clientId = ${clientId}`;
    yield* query`DELETE FROM oauthConsent WHERE clientId = ${clientId}`;
    yield* query`DELETE FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.query.client_id') = ${clientId}`;
    yield* query`DELETE FROM oauthAccessToken WHERE clientId = ${clientId}`;
    yield* query`DELETE FROM oauthRefreshToken WHERE clientId = ${clientId}`;

    return { revoked: true };
  });

  const cleanup = Effect.fn("Onboarding.cleanup")(function* () {
    const now = yield* Clock.currentTimeMillis;
    const cutoff = now - 7 * 24 * 60 * 60 * 1000;

    const stale = yield* Schema.decodeUnknownEffect(
      Schema.Array(Schema.Struct({ clientId: Schema.String })),
    )(
      yield* sql`SELECT p.clientId FROM clientOnboarding p JOIN oauthClient c ON c.clientId = p.clientId
        WHERE p.blocked = 0 AND c.createdAt < ${cutoff}
        AND NOT EXISTS (SELECT 1 FROM oauthConsent WHERE clientId = p.clientId)
        AND NOT EXISTS (SELECT 1 FROM oauthRefreshToken WHERE clientId = p.clientId AND expiresAt > ${now})
        AND NOT EXISTS (SELECT 1 FROM verification WHERE expiresAt > ${now} AND json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.query.client_id') = p.clientId)`,
    );

    for (const row of stale) {
      yield* revoke(row.clientId);
      yield* sql`DELETE FROM oauthClientResource WHERE clientId = ${row.clientId}`;
      yield* sql`DELETE FROM oauthClient WHERE clientId = ${row.clientId}`;
      yield* sql`DELETE FROM clientOnboarding WHERE clientId = ${row.clientId}`;
    }
  });

  return {
    list,
    cleanup,
    revoke: (clientId: string) => transaction(database, (sql) => revoke(clientId, sql)),
    admit: Effect.fn("Onboarding.admit")(function* () {
      yield* cleanup();
      const count = yield* sql`SELECT 1 FROM clientOnboarding LIMIT 1000`;

      return count.length < 1000;
    }),
    isBlocked: Effect.fn("Onboarding.isBlocked")(function* (clientId: string) {
      return (
        (yield* sql`SELECT 1 FROM clientOnboarding WHERE clientId = ${clientId} AND blocked = 1`)
          .length > 0
      );
    }),
    block: Effect.fn("Onboarding.block")(function* (clientId: string, blocked: boolean) {
      return yield* transaction(database, (sql) =>
        Effect.gen(function* () {
          if (
            !(yield* sql`SELECT 1 FROM oauthClient WHERE clientId = ${clientId} UNION SELECT 1 FROM clientOnboarding WHERE clientId = ${clientId}`)
              .length
          )
            return yield* Effect.fail(new APIError("NOT_FOUND", { message: "Client not found" }));
          yield* sql`UPDATE clientOnboarding SET blocked = ${blocked ? 1 : 0} WHERE clientId = ${clientId}`;
          // Managed clients use provider disabled; discovery additionally has a durable tombstone.
          yield* sql`UPDATE oauthClient SET disabled = ${blocked ? 1 : 0}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${clientId}`;

          if (blocked) yield* revoke(clientId, sql);

          return { blocked };
        }),
      );
    }),
  };
}
