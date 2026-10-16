import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { installPacked } from "../../../scripts/package-install.mjs";

const execute = promisify(execFile);

const root = fileURLToPath(new URL("../", import.meta.url));

const { name, version } = JSON.parse(await readFile(join(root, "package.json"), "utf8"));

const directory = await mkdtemp(join(tmpdir(), "clankerauth-admin-api-install-"));

try {
  await installPacked(directory, root, ["effect", "@gjermundgaraba/effect-actions"]);
  const installed = join(directory, "node_modules", name);
  const manifest = JSON.parse(await readFile(join(installed, "package.json"), "utf8"));
  assert.equal(manifest.version, version);
  assert.equal(manifest.private, undefined);
  assert.deepEqual(
    manifest.dependencies ?? {},
    {},
    "effect and effect-actions must be peers: a second copy would split their types and services",
  );
  assert.ok(manifest.peerDependencies.effect);
  assert.ok(manifest.peerDependencies["@gjermundgaraba/effect-actions"]);

  for (const [entry, target] of Object.entries(manifest.exports))
    assert.ok(
      (await readFile(join(installed, target.types), "utf8")).length > 0,
      `Entry point ships no declarations: ${entry}`,
    );

  await writeFile(
    join(directory, "consumer.ts"),
    `
import { Effect } from "effect";
import { HttpClient } from "effect/http";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { OwnerHttp, type ResourceNotFound } from "${name}";
const put = Effect.flatMap(ActionHttp.client(OwnerHttp, { baseUrl: "https://clankerauth.example" }), (admin) =>
  admin.putResource({ identifier: "https://notes.example/", name: "Notes", scopes: ["notes:read"] }),
);
const created: Effect.Effect<boolean, unknown, HttpClient.HttpClient> = Effect.map(put, ({ created }) => created);
const missing: ResourceNotFound["_tag"] = "ResourceNotFound";
void created;
void missing;
`,
  );
  await execute(
    process.execPath,
    [
      join(root, "node_modules/typescript/bin/tsc"),
      "--noEmit",
      "--strict",
      "--skipLibCheck",
      "--target",
      "ESNext",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      join(directory, "consumer.ts"),
    ],
    { cwd: directory },
  );

  await writeFile(
    join(directory, "load.mjs"),
    `import { Administration, OwnerHttp } from "${name}";\n` +
      `if (!Administration.some((action) => action.name === "putResource") || !OwnerHttp) process.exit(1);\n`,
  );
  await execute(process.execPath, ["load.mjs"], { cwd: directory });

  process.stdout.write(`${name}@${version} installs and loads\n`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
