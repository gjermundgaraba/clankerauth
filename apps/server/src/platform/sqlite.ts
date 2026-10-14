import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { Context, Effect, Exit, Layer, Schema } from "effect";
import { Kysely, sql as query } from "kysely";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { InternalServerError } from "@clankerauth/admin-api";

/** Cell values from node:sqlite / Kysely before Schema decoding at query sites. */
export type SqliteCell = string | number | bigint | boolean | null | Uint8Array;

/** Opaque Better Auth table row; decode columns with Schema before use. */
export type SqliteRow = Record<string, SqliteCell>;

/** Opaque Better Auth table map keyed by table name. */
export type DatabaseSchema = Record<string, SqliteRow>;

export const persisted = <T, RD>(schema: Schema.ConstraintDecoder<T, RD>) => {
  const decode = Schema.decodeUnknownEffect(schema);

  // eslint-disable-next-line anti-slop/no-unknown-parameters -- Persisted-row boundary: this is where the schema runs.
  return (value: unknown): Effect.Effect<T, InternalServerError, RD> =>
    Effect.mapError(decode(value), InternalServerError.of);
};

export function makeSql(database: Kysely<DatabaseSchema>) {
  return <Row = SqliteRow>(
    strings: TemplateStringsArray,
    ...parameters: readonly unknown[]
  ): Effect.Effect<readonly Row[], InternalServerError> =>
    Effect.tryPromise({
      try: async () => (await query<Row>(strings, ...parameters).execute(database)).rows,
      catch: InternalServerError.of,
    });
}

export type Sql = ReturnType<typeof makeSql>;

export const sqlFragment = (text: string) => query.raw(text);

export const transaction = Effect.fn("Database.transaction")(function* <A, E, R>(
  database: Kysely<DatabaseSchema>,
  operation: (sql: Sql) => Effect.Effect<A, E, R>,
) {
  const trx = yield* Effect.tryPromise({
    try: () => database.startTransaction().execute(),
    catch: InternalServerError.of,
  });

  const exit = yield* Effect.exit(operation(makeSql(trx)));

  const settle = Effect.ignore(
    Effect.tryPromise({ try: () => trx.rollback().execute(), catch: InternalServerError.of }),
  );

  const commit = Effect.tryPromise({
    try: () => trx.commit().execute(),
    catch: InternalServerError.of,
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

    // why: initializing the dialect makes Kysely own connection cleanup before any query
    await query`SELECT 1`.execute(kysely);

    return { kysely, sql: makeSql(kysely), close: () => kysely.destroy() };
  } catch (error) {
    database.close();
    throw error;
  }
}

export class Database extends Context.Service<
  Database,
  {
    /** The connection Better Auth runs on, for the provider's own adapter. */
    readonly kysely: Kysely<DatabaseSchema>;
    readonly sql: Sql;
    readonly transaction: <A, E, R>(
      operation: (sql: Sql) => Effect.Effect<A, E, R>,
    ) => Effect.Effect<A, E | InternalServerError, R>;
  }
>()("clankerauth/Database") {
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
