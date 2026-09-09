import { Effect, Schema } from "effect";
import { APIError } from "better-auth/api";
import type { SqlClient } from "effect/unstable/sql/SqlClient";

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
export function onboardingStore(sql: SqlClient) {
  const list = Effect.fn("Onboarding.list")(function* () {
    return (yield* rows(
      yield* sql`SELECT clientId AS client_id, source AS onboarding, blocked FROM clientOnboarding`,
    )).map((row) => ({ ...row, blocked: row.blocked !== 0 }));
  });
  const revoke = Effect.fn("Onboarding.revoke")(function* (clientId: string) {
    if (
      !(yield* sql`SELECT 1 FROM oauthClient WHERE clientId = ${clientId} UNION SELECT 1 FROM clientOnboarding WHERE clientId = ${clientId}`)
        .length
    )
      return yield* Effect.fail(new APIError("NOT_FOUND", { message: "Client not found" }));
    yield* sql`DELETE FROM oauthConsent WHERE clientId = ${clientId}`;
    yield* sql`DELETE FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.query.client_id') = ${clientId}`;
    yield* sql`DELETE FROM oauthAccessToken WHERE clientId = ${clientId}`;
    yield* sql`DELETE FROM oauthRefreshToken WHERE clientId = ${clientId}`;
    return { revoked: true };
  });
  const cleanup = Effect.fn("Onboarding.cleanup")(function* () {
    const now = Date.now();
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
    revoke: (clientId: string) => sql.withTransaction(revoke(clientId)),
    admit: Effect.fn("Onboarding.admit")(function* (clientId?: string) {
      if (clientId) {
        const policy =
          yield* sql`SELECT 1 FROM clientOnboarding WHERE clientId = ${clientId} AND blocked = 1`;
        if (policy.length) return false;
        if (
          (yield* sql`SELECT 1 FROM oauthClient WHERE clientId = ${clientId} UNION SELECT 1 FROM clientOnboarding WHERE clientId = ${clientId}`)
            .length
        )
          return true;
      }
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
      return yield* sql.withTransaction(
        Effect.gen(function* () {
          if (
            !(yield* sql`SELECT 1 FROM oauthClient WHERE clientId = ${clientId} UNION SELECT 1 FROM clientOnboarding WHERE clientId = ${clientId}`)
              .length
          )
            return yield* Effect.fail(new APIError("NOT_FOUND", { message: "Client not found" }));
          yield* sql`UPDATE clientOnboarding SET blocked = ${blocked ? 1 : 0} WHERE clientId = ${clientId}`;
          // Managed clients use provider disabled; discovery additionally has a durable tombstone.
          yield* sql`UPDATE oauthClient SET disabled = ${blocked ? 1 : 0}, updatedAt = ${Date.now()} WHERE clientId = ${clientId}`;
          if (blocked) yield* revoke(clientId);
          return { blocked };
        }),
      );
    }),
  };
}
