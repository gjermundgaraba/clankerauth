import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { Effect, Exit, Scope } from "effect";
import * as Reactivity from "effect/unstable/reactivity/Reactivity";
import {
  CompiledQuery,
  Kysely,
  SqliteAdapter,
  SqliteIntrospector,
  SqliteQueryCompiler,
  type DatabaseConnection,
  type Driver,
  type QueryResult,
} from "kysely";

/** Owns one SQLite connection; Effect SQL and Better Auth share its reservation lock. */
export async function openDatabase(filename: string) {
  const scope = Scope.makeUnsafe();
  try {
    const sql = await Effect.runPromise(
      SqliteClient.make({ filename }).pipe(Effect.provide(Reactivity.layer), Scope.provide(scope)),
    );
    const reservations = new Map<DatabaseConnection, Scope.Closeable>();
    const driver: Driver = {
      async init() {},
      async acquireConnection() {
        const reservation = Scope.makeUnsafe();
        try {
          const connection = await Effect.runPromise(sql.reserve.pipe(Scope.provide(reservation)));
          const wrapped: DatabaseConnection = {
            async executeQuery<R>(query: CompiledQuery): Promise<QueryResult<R>> {
              const result = await Effect.runPromise(
                connection.executeRaw(query.sql, query.parameters),
              );
              // The node SQLite driver returns rows for readers, and metadata for writes.
              if (Array.isArray(result)) return { rows: result };
              if (
                typeof result === "object" &&
                result !== null &&
                "changes" in result &&
                "lastInsertRowid" in result &&
                (typeof result.changes === "number" || typeof result.changes === "bigint") &&
                (typeof result.lastInsertRowid === "number" ||
                  typeof result.lastInsertRowid === "bigint")
              ) {
                return {
                  rows: [],
                  numAffectedRows: BigInt(result.changes),
                  insertId: BigInt(result.lastInsertRowid),
                };
              }
              throw new Error("Unexpected SQLite query result");
            },
            streamQuery() {
              throw new Error("SQLite query streaming is not supported");
            },
          };
          reservations.set(wrapped, reservation);
          return wrapped;
        } catch (error) {
          await Effect.runPromise(Scope.close(reservation, Exit.void));
          throw error;
        }
      },
      async beginTransaction(connection) {
        await connection.executeQuery(CompiledQuery.raw("BEGIN IMMEDIATE"));
      },
      async commitTransaction(connection) {
        await connection.executeQuery(CompiledQuery.raw("COMMIT"));
      },
      async rollbackTransaction(connection) {
        await connection.executeQuery(CompiledQuery.raw("ROLLBACK"));
      },
      async releaseConnection(connection) {
        const reservation = reservations.get(connection);
        if (reservation) {
          reservations.delete(connection);
          await Effect.runPromise(Scope.close(reservation, Exit.void));
        }
      },
      async destroy() {},
    };
    const kysely = new Kysely<Record<string, Record<string, unknown>>>({
      dialect: {
        createDriver: () => driver,
        createAdapter: () => new SqliteAdapter(),
        createQueryCompiler: () => new SqliteQueryCompiler(),
        createIntrospector: (db) => new SqliteIntrospector(db),
      },
    });
    return {
      sql,
      kysely,
      async close() {
        try {
          await kysely.destroy();
        } finally {
          await Effect.runPromise(Scope.close(scope, Exit.void));
        }
      },
    };
  } catch (error) {
    await Effect.runPromise(Scope.close(scope, Exit.void));
    throw error;
  }
}
