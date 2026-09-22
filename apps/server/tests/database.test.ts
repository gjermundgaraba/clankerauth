import { expect, test } from "vite-plus/test";
import { NotFound } from "@clankerauth/admin-api";
import { Cause, Effect, Exit, Result } from "effect";
import { sql as query } from "kysely";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeSql, openDatabase, transaction } from "../src/database.ts";

test("native SQLite queries share Kysely transactions and rollbacks", async () => {
  const database = await openDatabase(":memory:");

  try {
    await Effect.runPromise(
      database.sql`CREATE TABLE example (id INTEGER PRIMARY KEY, value TEXT)`,
    );

    const inserted = await query`INSERT INTO example (value) VALUES (${"first"})`.execute(
      database.kysely,
    );

    expect(inserted.numAffectedRows).toBe(1n);
    expect(inserted.insertId).toBe(1n);
    expect(await Effect.runPromise(database.sql`SELECT value FROM example`)).toEqual([
      { value: "first" },
    ]);

    let reader: Promise<unknown> | undefined;
    let readerCompleted = false;
    await expect(
      database.kysely.transaction().execute(async (transaction) => {
        const sql = makeSql(transaction);
        await Effect.runPromise(sql`INSERT INTO example (value) VALUES (${"rolled back"})`);
        expect(
          await Effect.runPromise(sql<{ value: string }>`SELECT value FROM example ORDER BY id`),
        ).toEqual([{ value: "first" }, { value: "rolled back" }]);
        reader = Effect.runPromise(database.sql`SELECT value FROM example`).then((rows) => {
          readerCompleted = true;

          return rows;
        });
        await new Promise<void>((resolve) => setImmediate(resolve));
        expect(readerCompleted).toBe(false);
        throw new Error("rollback requested");
      }),
    ).rejects.toThrow("rollback requested");
    expect(await reader).toEqual([{ value: "first" }]);

    await database.kysely.transaction().execute(async (transaction) => {
      await query`INSERT INTO example (value) VALUES (${"committed"})`.execute(transaction);
    });
    expect(await Effect.runPromise(database.sql`SELECT value FROM example ORDER BY id`)).toEqual([
      { value: "first" },
      { value: "committed" },
    ]);
    await expect(query`SELECT * FROM missing_table`.execute(database.kysely)).rejects.toThrow();
    expect((await query`SELECT * FROM example`.execute(database.kysely)).rows).toHaveLength(2);
  } finally {
    await database.close();
  }
});

test("native SQLite enables WAL, foreign keys, busy timeout and persists rows", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clankerauth-database-"));
  const filename = join(directory, "auth.sqlite");

  try {
    const database = await openDatabase(filename);

    try {
      expect(await Effect.runPromise(database.sql`PRAGMA journal_mode`)).toEqual([
        { journal_mode: "wal" },
      ]);
      expect(await Effect.runPromise(database.sql`PRAGMA foreign_keys`)).toEqual([
        { foreign_keys: 1 },
      ]);
      expect(await Effect.runPromise(database.sql`PRAGMA busy_timeout`)).toEqual([
        { timeout: 5000 },
      ]);
      await Effect.runPromise(database.sql`CREATE TABLE parent (id INTEGER PRIMARY KEY)`);
      await Effect.runPromise(
        database.sql`CREATE TABLE child (id INTEGER PRIMARY KEY, parentId INTEGER REFERENCES parent(id))`,
      );
      await expect(
        Effect.runPromise(database.sql`INSERT INTO child VALUES (1, 99)`),
      ).rejects.toThrow();
      await Effect.runPromise(database.sql`INSERT INTO parent VALUES (99)`);
      await Effect.runPromise(database.sql`INSERT INTO child VALUES (1, 99)`);
    } finally {
      await database.close();
    }

    await expect(Effect.runPromise(database.sql`SELECT 1`)).rejects.toThrow();

    const reopened = await openDatabase(filename);

    try {
      expect(await Effect.runPromise(reopened.sql`SELECT * FROM child`)).toEqual([
        { id: 1, parentId: 99 },
      ]);
    } finally {
      await reopened.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("local transactions preserve domain failures and roll back failed commits", async () => {
  const database = await openDatabase(":memory:");

  try {
    await Effect.runPromise(database.sql`CREATE TABLE parent (id INTEGER PRIMARY KEY)`);
    await Effect.runPromise(
      database.sql`CREATE TABLE child (parentId INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)`,
    );
    const error = new NotFound({ error: "Client not found" });
    await expect(
      Effect.runPromise(
        transaction(database.kysely, (sql) =>
          Effect.gen(function* () {
            yield* sql`INSERT INTO parent VALUES (1)`;

            return yield* Effect.fail(error);
          }),
        ),
      ),
    ).rejects.toBe(error);
    expect(await Effect.runPromise(database.sql`SELECT * FROM parent`)).toEqual([]);

    // The callback succeeds, but the deferred foreign key fails at COMMIT.
    await expect(
      Effect.runPromise(transaction(database.kysely, (sql) => sql`INSERT INTO child VALUES (99)`)),
    ).rejects.toBeInstanceOf(Error);
    expect(await Effect.runPromise(database.sql`SELECT * FROM child`)).toEqual([]);
    await Effect.runPromise(
      transaction(database.kysely, (sql) => sql`INSERT INTO parent VALUES (99)`),
    );
    expect(await Effect.runPromise(database.sql`SELECT * FROM parent`)).toEqual([{ id: 99 }]);
  } finally {
    await database.close();
  }
});

test("transactions preserve non-Error failures and defects after rollback", async () => {
  const database = await openDatabase(":memory:");
  const refusal = { reason: "denied" };
  const defect = new Error("programming error");

  try {
    await Effect.runPromise(database.sql`CREATE TABLE rollbackProbe (value TEXT)`);

    const failure = await Effect.runPromise(
      transaction(database.kysely, (sql) =>
        sql`INSERT INTO rollbackProbe VALUES ('failure')`.pipe(
          Effect.andThen(Effect.fail(refusal)),
        ),
      ).pipe(Effect.result),
    );

    expect(Result.isFailure(failure) && failure.failure).toBe(refusal);

    const exit = await Effect.runPromiseExit(
      transaction(database.kysely, (sql) =>
        sql`INSERT INTO rollbackProbe VALUES ('defect')`.pipe(Effect.andThen(Effect.die(defect))),
      ),
    );

    expect(Exit.isFailure(exit) && Cause.hasDies(exit.cause)).toBe(true);
    expect(await Effect.runPromise(database.sql`SELECT * FROM rollbackProbe`)).toEqual([]);
  } finally {
    await database.close();
  }
});
