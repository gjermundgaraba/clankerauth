import { expect, test } from "vite-plus/test";
import { Effect } from "effect";
import { sql as query } from "kysely";
import { openDatabase } from "../src/database.ts";

test("Kysely and Effect SQL share rows and transaction reservations", async () => {
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
        await query`INSERT INTO example (value) VALUES (${"rolled back"})`.execute(transaction);
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
