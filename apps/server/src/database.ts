import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { Effect, Exit } from "effect";
import { Kysely, sql as query } from "kysely";
import { DatabaseSync } from "node:sqlite";

export const normalizeError = (cause: unknown): Error =>
  cause instanceof Error ? cause : new Error(String(cause));

/** Cell values from node:sqlite / Kysely before Schema decoding at query sites. */
export type SqliteCell = string | number | bigint | boolean | null | Uint8Array;

/** Opaque Better Auth table row; decode columns with Schema before use. */
export type SqliteRow = Record<string, SqliteCell>;

/** Opaque Better Auth table map keyed by table name. */
export type DatabaseSchema = Record<string, SqliteRow>;

/** Run Effect queries through the same Kysely connection or transaction as Better Auth. */
export function makeSql(database: Kysely<DatabaseSchema>) {
  return <Row = SqliteRow>(
    strings: TemplateStringsArray,
    ...parameters: readonly unknown[]
  ): Effect.Effect<readonly Row[], Error> =>
    Effect.tryPromise({
      try: async () => (await query<Row>(strings, ...parameters).execute(database)).rows,
      catch: normalizeError,
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
    catch: normalizeError,
  });

  const exit = yield* Effect.exit(operation(makeSql(trx)));

  // The body's own outcome is what callers see; a failed ROLLBACK cannot improve on it.
  const settle = Effect.ignore(
    Effect.tryPromise({ try: () => trx.rollback().execute(), catch: normalizeError }),
  );

  // A failed COMMIT, such as a deferred constraint, leaves the transaction open on the
  // shared connection; roll it back before surfacing the failure.
  const commit = Effect.tryPromise({
    try: () => trx.commit().execute(),
    catch: normalizeError,
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
