import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../../../../", import.meta.url));

// why: fixtures run the installed linter on the repository's real policy, overrides included.
async function ruleLines(rule, folder, source, cwd = root) {
  const directory = await mkdtemp(join(root, folder, "lint-fixture-"));

  try {
    await writeFile(join(directory, "fixture.ts"), source);

    const result = spawnSync("vp", ["lint", join(directory, "fixture.ts"), "--format", "json"], {
      cwd,
      encoding: "utf8",
      timeout: 30_000,
    });

    assert.ifError(result.error);
    assert.notEqual(result.stdout, "", result.stderr);
    const { diagnostics } = JSON.parse(result.stdout);

    return diagnostics
      .filter((diagnostic) => diagnostic.code === `clankerauth(${rule})`)
      .map((diagnostic) => diagnostic.labels[0].span.line)
      .sort((a, b) => a - b);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

await test("a prose comment is refused, and a marked reason is one line", async () => {
  assert.deepEqual(
    await ruleLines(
      "no-prose-comments",
      "apps/server",
      [
        "#!/usr/bin/env node",
        "// Adds one.",
        "export const increment = (value: number) => value + 1;",
        "// why: the provider rejects a zero count.",
        "export const minimum = 1;",
        "// why: a reason",
        "// that continues.",
        "export const maximum = 2;",
      ].join("\n") + "\n",
    ),
    [2, 7],
  );
});

await test("type documentation and directives with a reason are kept, other doc blocks are not", async () => {
  assert.deepEqual(
    await ruleLines(
      "no-prose-comments",
      "apps/server",
      [
        "/** A count of attempts. */",
        "export interface Attempts {",
        "  /** How many remain. */",
        "  readonly remaining: number;",
        "}",
        "/** Builds attempts. */",
        "export const attempts = (remaining: number): Attempts => ({ remaining });",
        "// @ts-expect-error a string is not a count",
        "export const wrong: Attempts = { remaining: 'one' };",
        "// @ts-expect-error",
        "export const unexplained: Attempts = { remaining: 'two' };",
      ].join("\n") + "\n",
    ),
    [6, 10],
  );
});

await test("a schema is a type: its declaration and fields keep their documentation", async () => {
  assert.deepEqual(
    await ruleLines(
      "no-prose-comments",
      "apps/server",
      [
        'import { Schema } from "effect";',
        "/** A count of attempts. */",
        "export const Attempts = Schema.Struct({",
        "  /** How many remain. */",
        "  remaining: Schema.Number,",
        "});",
        "/** The attempts' own failure. */",
        'export class Exhausted extends Schema.TaggedError<Exhausted>()("Exhausted", {}) {}',
        "/** Builds attempts. */",
        "export const attempts = (remaining: number) => ({ remaining });",
        "export const options = {",
        "  /** How many to allow. */",
        "  remaining: 3,",
        "};",
      ].join("\n") + "\n",
    ),
    [9, 12],
  );
});

await test("the published SDK keeps its API documentation, and only the web app has section headers", async () => {
  assert.deepEqual(
    await ruleLines(
      "no-prose-comments",
      "packages/sdk/src",
      [
        "/** Builds a count. */",
        "export const count = (value: number) => value;",
        "// MODEL",
        "export const model = 1;",
      ].join("\n") + "\n",
    ),
    [3],
  );
  assert.deepEqual(
    await ruleLines("no-prose-comments", "apps/web/src", "// MODEL\n\nexport const model = 1;\n"),
    [],
  );
});

const imports = (...specifiers) =>
  specifiers.map((specifier) => `export * from "${specifier}";`).join("\n\n") + "\n";

await test("a domain folder imports Effect, the contracts and other domains, never a vendor or http/", async () => {
  assert.deepEqual(
    await ruleLines(
      "import-fence",
      "apps/server/src/clients",
      imports(
        "effect",
        "@clankerauth/admin-api",
        "../../platform/sqlite.ts",
        "kysely",
        "node:crypto",
        "../../http/actions.ts",
      ) + "\nexport const later = (name: string) => import(name);\n",
    ),
    [7, 9, 11, 13],
  );
});

await test("platform/ and issuer/ take technology, and http/ its own list", async () => {
  assert.deepEqual(
    await ruleLines("import-fence", "apps/server/src/platform", imports("kysely")),
    [],
  );
  assert.deepEqual(
    await ruleLines("import-fence", "apps/server/src/issuer", imports("better-auth/crypto")),
    [],
  );
  assert.deepEqual(
    await ruleLines("import-fence", "apps/server/src/http", imports("node:path", "kysely")),
    [3],
  );
});

await test("outside the server, only its embed entry is importable", async () => {
  assert.deepEqual(
    await ruleLines(
      "import-fence",
      "packages/dev/src",
      imports(
        "@clankerauth/server/embed",
        "@clankerauth/server/src/services.ts",
        "../../../../apps/server/src/services.ts",
      ),
    ),
    [3, 5],
  );
});

await test("the fence judges the same from inside a package as from the root", async () => {
  assert.deepEqual(
    await ruleLines(
      "import-fence",
      "apps/server/src/clients",
      imports("../../platform/sqlite.ts", "kysely"),
      join(root, "apps/server"),
    ),
    [3],
  );
  assert.deepEqual(
    await ruleLines(
      "import-fence",
      "packages/dev/src",
      imports("../../../../apps/server/src/services.ts"),
      join(root, "packages/dev"),
    ),
    [1],
  );
});

await test("Effect runs by hand only in entries and bridges, and tests bridge with runPromiseWith", async () => {
  const runs = [
    'import { Effect } from "effect";',
    "",
    "export const a = Effect.runPromise(Effect.void);",
    "",
    "export const b = Effect.runPromiseWith(Effect.context<never>)(Effect.void);",
  ].join("\n");

  assert.deepEqual(
    await ruleLines("no-manual-effect-run", "apps/server/src/clients", runs),
    [3, 5],
  );
  assert.deepEqual(await ruleLines("no-manual-effect-run", "apps/server/tests", runs), [3]);
});
