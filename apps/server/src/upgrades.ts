import { Effect, Schema } from "effect";
import type { Kysely } from "kysely";
import type { OwnerError } from "@clankerauth/admin-api";
import { persisted, transaction, type DatabaseSchema, type Sql } from "./database.ts";
import { clearGrants } from "./grants.ts";
import { administrationIdentifier, legacyAdministrationIdentifier } from "./resources.ts";

const decodeVersion = persisted(Schema.Tuple([Schema.Struct({ user_version: Schema.Number })]));

/**
 * Data changes the schema migrations cannot express, in release order. Each runs once, in
 * one transaction that ends by setting `user_version` to its position (PRAGMA takes no
 * parameters), so a restored backup runs them again.
 */
const steps: ReadonlyArray<(query: Sql, baseURL: string) => Effect.Effect<unknown, OwnerError>> = [
  // 0.10.0: earlier versions kept grants when access was removed, and only a link check at
  // refresh held them back; nothing checks links at refresh now. Automatic clients have no
  // links any more, so theirs go too.
  (query) =>
    Effect.gen(function* () {
      yield* clearGrants(query, {});
      yield* query`DELETE FROM oauthClientResource WHERE clientId IN (SELECT clientId FROM oauthClient WHERE userId IS NULL)`;
      yield* query`PRAGMA user_version = 1`;
    }),
  // 0.16.0: the administration resource is the issuer's origin root, as an application's is,
  // not `<baseURL>/mcp`. Tokens and consents name their resource, so the old ones go and
  // every administration client authorizes again; a managed client keeps its access. The
  // provider seeds the resource's name and scopes onto the renamed row when it starts.
  (query, baseURL) =>
    Effect.gen(function* () {
      const legacy = legacyAdministrationIdentifier(baseURL);
      const current = administrationIdentifier(baseURL);

      const held = (identifier: string) =>
        Effect.map(
          query`SELECT 1 FROM oauthResource WHERE identifier = ${identifier}`,
          (rows) => rows.length > 0,
        );

      // Only both names at once cannot be resolved. The current one alone, as in a database
      // created by this version and run through every step, needs nothing.
      if ((yield* held(legacy)) && (yield* held(current)))
        return yield* Effect.die(
          new Error(
            `A resource is registered at ${current}, which administration now takes: delete it and start again`,
          ),
        );

      yield* clearGrants(query, { resource: legacy });
      // Links name the resource by identifier; they are consistent again before commit.
      yield* query`PRAGMA defer_foreign_keys = ON`;
      yield* query`UPDATE oauthResource SET identifier = ${current} WHERE identifier = ${legacy}`;
      yield* query`UPDATE oauthClientResource SET resourceId = ${current} WHERE resourceId = ${legacy}`;
      yield* query`PRAGMA user_version = 2`;
    }),
];

/** Runs after the schema migrations and before the issuer serves anything. */
export const upgrade = Effect.fn("Database.upgrade")(function* (
  database: Kysely<DatabaseSchema>,
  sql: Sql,
  baseURL: string,
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
          yield* step(query, baseURL);

          // A step that misnumbers itself would skip or repeat the ones after it.
          if ((yield* version(query)) !== index + 1)
            return yield* Effect.die(
              new Error(`Upgrade step ${index} must set user_version = ${index + 1}`),
            );
        }),
      );
});
