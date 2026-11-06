import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Schema } from "effect";

import {
  assertDeclarations,
  execute,
  installPacked,
} from "../../../scripts/package-install.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));

const serverRequire = createRequire(
  new URL("../../../apps/server/package.json", import.meta.url)
);

const Release = Schema.Struct({ version: Schema.String });

const Manifest = Schema.Struct({
  ...Release.fields,
  name: Schema.String,
  dependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  exports: Schema.Record(
    Schema.String,
    Schema.Struct({ types: Schema.String })
  ),
});

const decodeManifest = Schema.decodeUnknownSync(
  Schema.fromJsonString(Manifest)
);

const decodeRelease = Schema.decodeUnknownSync(Schema.fromJsonString(Release));

/** @param {string} directory */
const readManifest = async (directory) =>
  decodeManifest(await readFile(path.join(directory, "package.json"), "utf-8"));

const { name, version } = await readManifest(root);

const directory = await mkdtemp(
  path.join(tmpdir(), "clankerauth-dev-install-")
);

try {
  await installPacked(directory, root, [], { offline: true });
  const installed = path.join(directory, "node_modules", name);

  const manifest = await readManifest(installed);

  assert.equal(manifest.version, version);
  assert.deepEqual(manifest.dependencies ?? {}, {});
  await assertDeclarations(installed, manifest.exports);

  const notices = await readFile(
    path.join(installed, "dist/THIRD_PARTY_NOTICES.txt"),
    "utf-8"
  );

  const headings = new Set(
    notices.split("\n---\n\n").map((section) => section.split("\n")[0])
  );

  for (const provider of [
    "@better-auth/api-key",
    "@better-auth/oauth-provider",
  ]) {
    const manifestPath = path.join(
      path.dirname(serverRequire.resolve(provider)),
      "../package.json"
    );

    const { version: providerVersion } = decodeRelease(
      await readFile(manifestPath, "utf-8")
    );

    const heading = `${provider}@${providerVersion}`;
    assert.ok(
      headings.has(heading),
      `Missing bundled dependency notice: ${heading}`
    );
  }

  const lifecycle = await readFile(
    path.join(root, "tests/lifecycle.test.mts"),
    "utf-8"
  );

  await writeFile(path.join(directory, "installed.test.mts"), lifecycle);

  const result = await execute(
    process.execPath,
    ["--test", "installed.test.mts"],
    {
      cwd: directory,
      timeout: 60_000,
    }
  );

  process.stdout.write(result.stdout);
} finally {
  await rm(directory, { recursive: true, force: true });
}
