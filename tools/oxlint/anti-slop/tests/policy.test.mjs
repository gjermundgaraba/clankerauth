import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../../../../", import.meta.url));

// Exercise the installed runner, including plugin loading and inline directives.
// Fixtures use the real repository policy and resolve the server dependencies.
// Do not override rule activation or ignores: those are part of the policy under test.
async function lint(source, expectedRule, filename = "consumer.ts") {
  const directory = await mkdtemp(join(root, "apps/server/lint-fixture-"));
  try {
    await writeFile(join(directory, "database.ts"), "export const makeSql = () => 1;\n");
    await writeFile(join(directory, "session.ts"), "export const makeSession = () => 1;\n");
    await writeFile(join(directory, filename), source);
    const result = spawnSync("vp", [
      "lint", join(directory, filename), "--format", "json",
      "--report-unused-disable-directives-severity", "error",
    ], { cwd: root, encoding: "utf8", timeout: 30_000 });
    assert.ifError(result.error);
    assert.equal(result.signal, null, result.stderr);
    assert.notEqual(result.stdout, "", result.stderr);
    const output = JSON.parse(result.stdout);
    const [plugin, name] = expectedRule.split("/");
    for (const diagnostic of output.diagnostics) {
      assert.equal(diagnostic.code, `${plugin}(${name})`, JSON.stringify(diagnostic));
    }
    return { status: result.status, diagnostics: output.diagnostics };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("unknown input stays prohibited in domain operations", async () => {
  const result = await lint(
    "export function updateResource(input: unknown) { return input; }",
    "anti-slop/no-unknown-parameters",
  );
  assert.equal(result.status, 1);
  assert.equal(result.diagnostics.length, 1);
  assert.match(result.diagnostics[0].message, /input/);
});

test("documented decoder boundary passes without an unused suppression", async () => {
  const result = await lint(`
    import { Schema } from "effect";

    const Row = Schema.Struct({ name: Schema.String });

    // eslint-disable-next-line anti-slop/no-unknown-parameters -- Persisted-row boundary: decode before use.
    export const decodeRow = (value: unknown) => Schema.decodeUnknownEffect(Row)(value);
  `, "anti-slop/no-unknown-parameters");
  assert.equal(result.status, 0, JSON.stringify(result.diagnostics));
  assert.deepEqual(result.diagnostics, []);
});

test("constructor restriction catches aliases too", async () => {
  const result = await lint(
    'import { makeSession as construct } from "./session.ts"; \n\nexport { construct };',
    "anti-slop-effect/no-service-constructor-imports",
  );
  assert.equal(result.status, 1);
  assert.equal(result.diagnostics.length, 1);
  assert.match(result.diagnostics[0].message, /makeSession/);
});

test("documented adapter import passes without an unused suppression", async () => {
  const result = await lint(`
    // eslint-disable-next-line anti-slop-effect/no-service-constructor-imports -- Adapts an owned connection, not a contextual service.
    import { makeSql } from "./database.ts";

    export { makeSql };
  `, "anti-slop-effect/no-service-constructor-imports");
  assert.equal(result.status, 0, JSON.stringify(result.diagnostics));
  assert.deepEqual(result.diagnostics, []);
});

test("tagged wire expectations use constructors and encoders", async () => {
  const result = await lint(`
    import { Schema } from "effect";
    import { BadRequest } from "@clankerauth/api";

    export const expected = Schema.encodeSync(BadRequest)(new BadRequest({ error: "Invalid request" }));
  `, "anti-slop-effect/no-manual-tagged-construction", "contract.test.ts");
  assert.equal(result.status, 0, JSON.stringify(result.diagnostics));
  assert.deepEqual(result.diagnostics, []);
});

test("tests are not blanket-exempted from tagged construction", async () => {
  const result = await lint(
    'export const expected = { _tag: "BadRequest", error: "Invalid request" };',
    "anti-slop-effect/no-manual-tagged-construction", "contract.test.ts",
  );
  assert.equal(result.status, 1);
  assert.equal(result.diagnostics.length, 1);
});

test("actual boundary exceptions remain valid under repository configuration", () => {
  const result = spawnSync("vp", [
    "lint", "apps/server/src/onboarding.ts", "apps/server/src/resources.ts",
    "--report-unused-disable-directives-severity", "error",
  ], { cwd: root, encoding: "utf8", timeout: 30_000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
