import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { Effect } from "effect";
import { Kysely, sql as query } from "kysely";
import { DatabaseSync } from "node:sqlite";

export const normalizeError = (error: unknown): Error =>
  error instanceof Error ? error : new Error(String(error));

export type DatabaseSchema = Record<string, Record<string, unknown>>;

/** Run Effect queries through the same Kysely connection or transaction as Better Auth. */
export function makeSql(database: Kysely<DatabaseSchema>) {
  return <Row = Record<string, unknown>>(
    strings: TemplateStringsArray,
    ...parameters: readonly unknown[]
  ): Effect.Effect<readonly Row[], Error> =>
    Effect.tryPromise({
      try: async () => (await query<Row>(strings, ...parameters).execute(database)).rows,
      catch: normalizeError,
    });
}

export type Sql = ReturnType<typeof makeSql>;

/** Keep local writes atomic while preserving domain errors across the Promise boundary. */
export function transaction<A>(
  database: Kysely<DatabaseSchema>,
  operation: (sql: Sql) => Effect.Effect<A, Error>,
): Effect.Effect<A, Error> {
  return Effect.tryPromise({
    try: () => database.transaction().execute((trx) => Effect.runPromise(operation(makeSql(trx)))),
    catch: normalizeError,
  });
}

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
