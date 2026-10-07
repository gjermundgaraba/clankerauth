import { Effect, Schema } from "effect";
import type { Kysely } from "kysely";
import type { OwnerError } from "@clankerauth/admin-api";
import { persisted, transaction, type DatabaseSchema, type Sql } from "./database.ts";
import { clearGrants } from "./grants.ts";

const decodeVersion = persisted(Schema.Tuple([Schema.Struct({ user_version: Schema.Number })]));

/**
 * Data changes the schema migrations cannot express, in release order. Each runs once, in
 * one transaction that ends by setting `user_version` to its position (PRAGMA takes no
 * parameters), so a restored backup runs them again.
 */
const steps: ReadonlyArray<(query: Sql) => Effect.Effect<unknown, OwnerError>> = [
  // 0.10.0: earlier versions kept grants when access was removed, and only a link check at
  // refresh held them back; nothing checks links at refresh now. Automatic clients have no
  // links any more, so theirs go too.
  (query) =>
    Effect.gen(function* () {
      yield* clearGrants(query, {});
      yield* query`DELETE FROM oauthClientResource WHERE clientId IN (SELECT clientId FROM oauthClient WHERE userId IS NULL)`;
      yield* query`PRAGMA user_version = 1`;
    }),
];

/** Runs after the schema migrations and before the issuer serves anything. */
export const upgrade = Effect.fn("Database.upgrade")(function* (
  database: Kysely<DatabaseSchema>,
  sql: Sql,
) {
  const version = (query: Sql) =>
    Effect.map(
      Effect.flatMap(query`PRAGMA user_version`, decodeVersion),
      ([row]) => row.user_version,
    );

  const current = yield* version(sql);

  for (const [index, step] of steps.entries())
    if (index >= current)
      yield* transaction(database, (query) =>
        Effect.gen(function* () {
          yield* step(query);

          // A step that misnumbers itself would skip or repeat the ones after it.
          if ((yield* version(query)) !== index + 1)
            return yield* Effect.die(
              new Error(`Upgrade step ${index} must set user_version = ${index + 1}`),
            );
        }),
      );
});
