import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setImmediate as nextTurn } from "node:timers/promises";

import { it } from "@effect/vitest";
import { ClientNotFound } from "@gjermundgaraba/clankerauth-admin-api";
import { Cause, Effect, Exit, Result } from "effect";
import { sql as query } from "kysely";
import { expect } from "vite-plus/test";

import {
  makeSql,
  openDatabase,
  transaction,
} from "../../src/platform/sqlite.ts";

const plain = (rows: readonly object[]) => rows.map((row) => ({ ...row }));

const open = (filename: string) =>
  Effect.acquireRelease(
    Effect.promise(async () => await openDatabase(filename)),
    (database) =>
      Effect.promise(async () => {
        await database.close();
      })
  );

it.live("native SQLite queries share Kysely transactions and rollbacks", () =>
  Effect.gen(function* () {
    const database = yield* open(":memory:");
    const services = yield* Effect.context();

    yield* database.sql`CREATE TABLE example (id INTEGER PRIMARY KEY, value TEXT)`;

    const inserted = yield* Effect.promise(
      async () =>
        await query`INSERT INTO example (value) VALUES (${"first"})`.execute(
          database.kysely
        )
    );

    expect(inserted.numAffectedRows).toBe(1n);
    expect(inserted.insertId).toBe(1n);
    expect(plain(yield* database.sql`SELECT value FROM example`)).toStrictEqual(
      [{ value: "first" }]
    );

    let reader: Promise<readonly object[]> | undefined;
    let readerCompleted = false;

    const rollback = yield* Effect.flip(
      Effect.tryPromise({
        try: async () =>
          await database.kysely.transaction().execute(async (trx) => {
            const sql = makeSql(trx);
            await Effect.runPromiseWith(services)(
              sql`INSERT INTO example (value) VALUES (${"rolled back"})`
            );
            await expect(
              Effect.runPromiseWith(services)(
                sql<{ value: string }>`SELECT value FROM example ORDER BY id`
              ).then(plain)
            ).resolves.toStrictEqual([
              { value: "first" },
              { value: "rolled back" },
            ]);
            reader = Effect.runPromiseWith(services)(
              database.sql`SELECT value FROM example`
            ).then((rows) => {
              readerCompleted = true;

              return rows;
            });
            await nextTurn();
            expect(readerCompleted).toBe(false);
            throw new Error("rollback requested");
          }),
        catch: (error) =>
          error instanceof Error ? error.message : String(error),
      })
    );

    expect(rollback).toBe("rollback requested");
    expect(
      plain(yield* Effect.promise(async () => await reader!))
    ).toStrictEqual([{ value: "first" }]);

    yield* Effect.promise(async () => {
      await database.kysely.transaction().execute(async (trx) => {
        await query`INSERT INTO example (value) VALUES (${"committed"})`.execute(
          trx
        );
      });
    });
    expect(
      plain(yield* database.sql`SELECT value FROM example ORDER BY id`)
    ).toStrictEqual([{ value: "first" }, { value: "committed" }]);
    yield* Effect.flip(
      Effect.tryPromise(
        async () =>
          await query`SELECT * FROM missing_table`.execute(database.kysely)
      )
    );
    expect(
      (yield* Effect.promise(
        async () => await query`SELECT * FROM example`.execute(database.kysely)
      )).rows
    ).toHaveLength(2);
  })
);

it.effect(
  "native SQLite enables WAL, foreign keys, busy timeout and persists rows",
  () =>
    Effect.gen(function* () {
      const directory = yield* Effect.acquireRelease(
        Effect.promise(
          async () =>
            await mkdtemp(path.join(tmpdir(), "clankerauth-database-"))
        ),
        (created) =>
          Effect.promise(async () => {
            await rm(created, { recursive: true, force: true });
          })
      );

      const filename = path.join(directory, "clankerauth.sqlite");

      const closed = yield* Effect.scoped(
        Effect.gen(function* () {
          const database = yield* open(filename);

          expect(plain(yield* database.sql`PRAGMA journal_mode`)).toStrictEqual(
            [{ journal_mode: "wal" }]
          );
          expect(plain(yield* database.sql`PRAGMA foreign_keys`)).toStrictEqual(
            [{ foreign_keys: 1 }]
          );
          expect(plain(yield* database.sql`PRAGMA busy_timeout`)).toStrictEqual(
            [{ timeout: 5000 }]
          );
          yield* database.sql`CREATE TABLE parent (id INTEGER PRIMARY KEY)`;
          yield* database.sql`CREATE TABLE child (id INTEGER PRIMARY KEY, parentId INTEGER REFERENCES parent(id))`;
          yield* Effect.flip(database.sql`INSERT INTO child VALUES (1, 99)`);
          yield* database.sql`INSERT INTO parent VALUES (99)`;
          yield* database.sql`INSERT INTO child VALUES (1, 99)`;

          return database;
        })
      );

      yield* Effect.flip(closed.sql`SELECT 1`);

      const reopened = yield* open(filename);

      expect(plain(yield* reopened.sql`SELECT * FROM child`)).toStrictEqual([
        { id: 1, parentId: 99 },
      ]);
    })
);

it.effect(
  "local transactions preserve domain failures and roll back failed commits",
  () =>
    Effect.gen(function* () {
      const database = yield* open(":memory:");

      yield* database.sql`CREATE TABLE parent (id INTEGER PRIMARY KEY)`;
      yield* database.sql`CREATE TABLE child (parentId INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)`;
      const error = ClientNotFound.of("missing");
      expect(
        yield* Effect.flip(
          transaction(database.kysely, (sql) =>
            Effect.gen(function* () {
              yield* sql`INSERT INTO parent VALUES (1)`;

              return yield* error;
            })
          )
        )
      ).toBe(error);
      expect(yield* database.sql`SELECT * FROM parent`).toStrictEqual([]);

      expect(
        yield* Effect.flip(
          transaction(
            database.kysely,
            (sql) => sql`INSERT INTO child VALUES (99)`
          )
        )
      ).toBeInstanceOf(Error);
      expect(yield* database.sql`SELECT * FROM child`).toStrictEqual([]);
      yield* transaction(
        database.kysely,
        (sql) => sql`INSERT INTO parent VALUES (99)`
      );
      expect(plain(yield* database.sql`SELECT * FROM parent`)).toStrictEqual([
        { id: 99 },
      ]);
    })
);

it.effect(
  "transactions preserve non-Error failures and defects after rollback",
  () =>
    Effect.gen(function* () {
      const database = yield* open(":memory:");
      const refusal = { reason: "denied" };
      const defect = new Error("programming error");

      yield* database.sql`CREATE TABLE rollbackProbe (value TEXT)`;

      const failure = yield* transaction(database.kysely, (sql) =>
        sql`INSERT INTO rollbackProbe VALUES ('failure')`.pipe(
          Effect.andThen(Effect.fail(refusal))
        )
      ).pipe(Effect.result);

      expect(Result.isFailure(failure) && failure.failure).toBe(refusal);

      const exit = yield* Effect.exit(
        transaction(database.kysely, (sql) =>
          sql`INSERT INTO rollbackProbe VALUES ('defect')`.pipe(
            Effect.andThen(Effect.die(defect))
          )
        )
      );

      expect(Exit.isFailure(exit) && Cause.hasDies(exit.cause)).toBe(true);
      expect(yield* database.sql`SELECT * FROM rollbackProbe`).toStrictEqual(
        []
      );
    })
);
