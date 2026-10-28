import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { InternalServerError } from "@gjermundgaraba/clankerauth-admin-api";
import { Context, Effect, Exit, Layer, Schema } from "effect";
import { Kysely, sql as query } from "kysely";

export type SqliteCell = string | number | bigint | boolean | null | Uint8Array;

export type SqliteRow = Record<string, SqliteCell>;

export type Persisted =
  | SqliteCell
  | SqliteRow
  | readonly SqliteRow[]
  | undefined;

export type DatabaseSchema = Record<string, SqliteRow>;

export const persisted = <T, RD>(schema: Schema.ConstraintDecoder<T, RD>) => {
  const decode = Schema.decodeUnknownEffect(schema);

  return (value: Persisted): Effect.Effect<T, InternalServerError, RD> =>
    Effect.mapError(decode(value), InternalServerError.of);
};

export const makeSql =
  (database: Kysely<DatabaseSchema>) =>
  <Row = SqliteRow>(
    strings: TemplateStringsArray,
    ...parameters: readonly unknown[]
  ): Effect.Effect<readonly Row[], InternalServerError> =>
    Effect.tryPromise({
      try: async () => {
        const { rows } = await query<Row>(strings, ...parameters).execute(
          database
        );

        return rows;
      },
      catch: InternalServerError.of,
    });

export type Sql = ReturnType<typeof makeSql>;

export const transaction = Effect.fn("Database.transaction")(function* <
  A,
  E,
  R,
>(
  database: Kysely<DatabaseSchema>,
  operation: (sql: Sql) => Effect.Effect<A, E, R>
) {
  const trx = yield* Effect.tryPromise({
    try: async () => await database.startTransaction().execute(),
    catch: InternalServerError.of,
  });

  const exit = yield* Effect.exit(operation(makeSql(trx)));

  const settle = Effect.ignore(
    Effect.tryPromise({
      try: async () => {
        await trx.rollback().execute();
      },
      catch: InternalServerError.of,
    })
  );

  const commit = Effect.tryPromise({
    try: async () => {
      await trx.commit().execute();
    },
    catch: InternalServerError.of,
  }).pipe(Effect.tapError(() => settle));

  yield* Exit.isSuccess(exit) ? commit : settle;

  return yield* exit;
}, Effect.uninterruptible);

export const openDatabase = async (filename: string) => {
  const database = new DatabaseSync(filename);

  try {
    database.exec(
      "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;"
    );

    const kysely = new Kysely<DatabaseSchema>({
      dialect: new NodeSqliteDialect({ database }),
    });

    await query`SELECT 1`.execute(kysely);

    return {
      kysely,
      sql: makeSql(kysely),
      close: async () => {
        await kysely.destroy();
      },
    };
  } catch (error) {
    database.close();
    throw error;
  }
};

export class Database extends Context.Service<
  Database,
  {
    readonly kysely: Kysely<DatabaseSchema>;
    readonly sql: Sql;
    readonly transaction: <A, E, R>(
      operation: (sql: Sql) => Effect.Effect<A, E, R>
    ) => Effect.Effect<A, E | InternalServerError, R>;
  }
>()("clankerauth/Database") {
  static readonly layer = (filename: string) =>
    Layer.effect(
      Database,
      Effect.gen(function* () {
        yield* Effect.try(() =>
          mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 })
        );

        const open = yield* Effect.acquireRelease(
          Effect.tryPromise(async () => await openDatabase(filename)),
          (database) =>
            Effect.promise(async () => {
              await database.close();
            })
        );

        return {
          kysely: open.kysely,
          sql: open.sql,
          transaction: (operation) => transaction(open.kysely, operation),
        };
      })
    );
}
