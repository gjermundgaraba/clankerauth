import { it } from "@effect/vitest";
import { expect } from "vite-plus/test";
import { ClientNotFound } from "@clankerauth/admin-api";
import { Cause, Effect, Exit, Result } from "effect";
import { sql as query } from "kysely";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeSql, openDatabase, transaction } from "../../src/platform/sqlite.ts";

const open = (filename: string) =>
  Effect.acquireRelease(
    Effect.promise(() => openDatabase(filename)),
    (database) => Effect.promise(() => database.close()),
  );

it.live("native SQLite queries share Kysely transactions and rollbacks", () =>
  Effect.gen(function* () {
    const database = yield* open(":memory:");
    const services = yield* Effect.context<never>();

    yield* database.sql`CREATE TABLE example (id INTEGER PRIMARY KEY, value TEXT)`;

    const inserted = yield* Effect.promise(() =>
      query`INSERT INTO example (value) VALUES (${"first"})`.execute(database.kysely),
    );

    expect(inserted.numAffectedRows).toBe(1n);
    expect(inserted.insertId).toBe(1n);
    expect(yield* database.sql`SELECT value FROM example`).toEqual([{ value: "first" }]);

    let reader: Promise<unknown> | undefined;
    let readerCompleted = false;

    const rollback = yield* Effect.flip(
      Effect.tryPromise({
        try: () =>
          database.kysely.transaction().execute(async (transaction) => {
            const sql = makeSql(transaction);
            await Effect.runPromiseWith(services)(
              sql`INSERT INTO example (value) VALUES (${"rolled back"})`,
            );
            expect(
              await Effect.runPromiseWith(services)(
                sql<{ value: string }>`SELECT value FROM example ORDER BY id`,
              ),
            ).toEqual([{ value: "first" }, { value: "rolled back" }]);
            reader = Effect.runPromiseWith(services)(database.sql`SELECT value FROM example`).then(
              (rows) => {
                readerCompleted = true;

                return rows;
              },
            );
            await new Promise<void>((resolve) => setImmediate(resolve));
            expect(readerCompleted).toBe(false);
            throw new Error("rollback requested");
          }),
        catch: (error) => error,
      }),
    );

    expect(rollback).toHaveProperty("message", "rollback requested");
    expect(yield* Effect.promise(async () => reader)).toEqual([{ value: "first" }]);

    yield* Effect.promise(() =>
      database.kysely.transaction().execute(async (transaction) => {
        await query`INSERT INTO example (value) VALUES (${"committed"})`.execute(transaction);
      }),
    );
    expect(yield* database.sql`SELECT value FROM example ORDER BY id`).toEqual([
      { value: "first" },
      { value: "committed" },
    ]);
    yield* Effect.flip(
      Effect.tryPromise(() => query`SELECT * FROM missing_table`.execute(database.kysely)),
    );
    expect(
      (yield* Effect.promise(() => query`SELECT * FROM example`.execute(database.kysely))).rows,
    ).toHaveLength(2);
  }),
);

it.effect("native SQLite enables WAL, foreign keys, busy timeout and persists rows", () =>
  Effect.gen(function* () {
    const directory = yield* Effect.acquireRelease(
      Effect.promise(() => mkdtemp(join(tmpdir(), "clankerauth-database-"))),
      (directory) => Effect.promise(() => rm(directory, { recursive: true, force: true })),
    );

    const filename = join(directory, "clankerauth.sqlite");

    const database = yield* Effect.scoped(
      Effect.gen(function* () {
        const database = yield* open(filename);

        expect(yield* database.sql`PRAGMA journal_mode`).toEqual([{ journal_mode: "wal" }]);
        expect(yield* database.sql`PRAGMA foreign_keys`).toEqual([{ foreign_keys: 1 }]);
        expect(yield* database.sql`PRAGMA busy_timeout`).toEqual([{ timeout: 5000 }]);
        yield* database.sql`CREATE TABLE parent (id INTEGER PRIMARY KEY)`;
        yield* database.sql`CREATE TABLE child (id INTEGER PRIMARY KEY, parentId INTEGER REFERENCES parent(id))`;
        yield* Effect.flip(database.sql`INSERT INTO child VALUES (1, 99)`);
        yield* database.sql`INSERT INTO parent VALUES (99)`;
        yield* database.sql`INSERT INTO child VALUES (1, 99)`;

        return database;
      }),
    );

    yield* Effect.flip(database.sql`SELECT 1`);

    const reopened = yield* open(filename);

    expect(yield* reopened.sql`SELECT * FROM child`).toEqual([{ id: 1, parentId: 99 }]);
  }),
);

it.effect("local transactions preserve domain failures and roll back failed commits", () =>
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

            return yield* Effect.fail(error);
          }),
        ),
      ),
    ).toBe(error);
    expect(yield* database.sql`SELECT * FROM parent`).toEqual([]);

    expect(
      yield* Effect.flip(transaction(database.kysely, (sql) => sql`INSERT INTO child VALUES (99)`)),
    ).toBeInstanceOf(Error);
    expect(yield* database.sql`SELECT * FROM child`).toEqual([]);
    yield* transaction(database.kysely, (sql) => sql`INSERT INTO parent VALUES (99)`);
    expect(yield* database.sql`SELECT * FROM parent`).toEqual([{ id: 99 }]);
  }),
);

it.effect("transactions preserve non-Error failures and defects after rollback", () =>
  Effect.gen(function* () {
    const database = yield* open(":memory:");
    const refusal = { reason: "denied" };
    const defect = new Error("programming error");

    yield* database.sql`CREATE TABLE rollbackProbe (value TEXT)`;

    const failure = yield* transaction(database.kysely, (sql) =>
      sql`INSERT INTO rollbackProbe VALUES ('failure')`.pipe(Effect.andThen(Effect.fail(refusal))),
    ).pipe(Effect.result);

    expect(Result.isFailure(failure) && failure.failure).toBe(refusal);

    const exit = yield* Effect.exit(
      transaction(database.kysely, (sql) =>
        sql`INSERT INTO rollbackProbe VALUES ('defect')`.pipe(Effect.andThen(Effect.die(defect))),
      ),
    );

    expect(Exit.isFailure(exit) && Cause.hasDies(exit.cause)).toBe(true);
    expect(yield* database.sql`SELECT * FROM rollbackProbe`).toEqual([]);
  }),
);
