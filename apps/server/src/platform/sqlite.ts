import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { Context, Effect, Exit, Layer, Schema } from "effect";
import { Kysely, sql as query } from "kysely";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { OwnerError } from "@clankerauth/admin-api";
import { internalError } from "../issuer/errors.ts";

/** Cell values from node:sqlite / Kysely before Schema decoding at query sites. */
export type SqliteCell = string | number | bigint | boolean | null | Uint8Array;

/** Opaque Better Auth table row; decode columns with Schema before use. */
export type SqliteRow = Record<string, SqliteCell>;

/** Opaque Better Auth table map keyed by table name. */
export type DatabaseSchema = Record<string, SqliteRow>;

/**
 * A decoder for values this issuer wrote itself. A row or column that no longer
 * matches its schema is a broken database, not a bad request, so it fails as an
 * internal error carrying the schema issue.
 */
export const persisted = <T, RD>(schema: Schema.ConstraintDecoder<T, RD>) => {
  const decode = Schema.decodeUnknownEffect(schema);

  // eslint-disable-next-line anti-slop/no-unknown-parameters -- Persisted-row boundary: this is where the schema runs.
  return (value: unknown): Effect.Effect<T, OwnerError, RD> =>
    Effect.mapError(decode(value), internalError);
};

/** Run Effect queries through the same Kysely connection or transaction as Better Auth. */
export function makeSql(database: Kysely<DatabaseSchema>) {
  return <Row = SqliteRow>(
    strings: TemplateStringsArray,
    ...parameters: readonly unknown[]
  ): Effect.Effect<readonly Row[], OwnerError> =>
    Effect.tryPromise({
      try: async () => (await query<Row>(strings, ...parameters).execute(database)).rows,
      catch: internalError,
    });
}

export type Sql = ReturnType<typeof makeSql>;

/** Commit on success, roll back on failure or defect; a started transaction always settles. */
export const transaction = Effect.fn("Database.transaction")(function* <A, E, R>(
  database: Kysely<DatabaseSchema>,
  operation: (sql: Sql) => Effect.Effect<A, E, R>,
) {
  const trx = yield* Effect.tryPromise({
    try: () => database.startTransaction().execute(),
    catch: internalError,
  });

  const exit = yield* Effect.exit(operation(makeSql(trx)));

  // The body's own outcome is what callers see; a failed ROLLBACK cannot improve on it.
  const settle = Effect.ignore(
    Effect.tryPromise({ try: () => trx.rollback().execute(), catch: internalError }),
  );

  // A failed COMMIT, such as a deferred constraint, leaves the transaction open on the
  // shared connection; roll it back before surfacing the failure.
  const commit = Effect.tryPromise({
    try: () => trx.commit().execute(),
    catch: internalError,
  }).pipe(Effect.tapError(() => settle));

  yield* Exit.isSuccess(exit) ? commit : settle;

  return yield* exit;
}, Effect.uninterruptible);

export async function openDatabase(filename: string) {
  const database = new DatabaseSync(filename);

  try {
    database.exec(
      "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
    );

    const kysely = new Kysely<DatabaseSchema>({
      dialect: new NodeSqliteDialect({ database }),
    });

    // Initialize the dialect so Kysely owns connection cleanup even before the first caller query.
    await query`SELECT 1`.execute(kysely);

    return { kysely, sql: makeSql(kysely), close: () => kysely.destroy() };
  } catch (error) {
    database.close();
    throw error;
  }
}

/** The issuer's one SQLite connection, shared by Better Auth and every domain's queries. */
export class Database extends Context.Service<
  Database,
  {
    /** The connection Better Auth runs on, for the provider's own adapter. */
    readonly kysely: Kysely<DatabaseSchema>;
    readonly sql: Sql;
    readonly transaction: <A, E, R>(
      operation: (sql: Sql) => Effect.Effect<A, E, R>,
    ) => Effect.Effect<A, E | OwnerError, R>;
  }
>()("clankerauth/Database") {
  /** Opens `filename`, creating its directory, and closes the connection with the scope. */
  static readonly layer = (filename: string) =>
    Layer.effect(
      Database,
      Effect.gen(function* () {
        yield* Effect.try(() => mkdirSync(dirname(filename), { recursive: true, mode: 0o700 }));

        const open = yield* Effect.acquireRelease(
          Effect.tryPromise(() => openDatabase(filename)),
          (database) => Effect.promise(() => database.close()),
        );

        return {
          kysely: open.kysely,
          sql: open.sql,
          transaction: (operation) => transaction(open.kysely, operation),
        };
      }),
    );
}
