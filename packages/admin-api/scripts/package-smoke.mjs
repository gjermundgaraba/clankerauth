import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

const Manifest = Schema.Struct({
  name: Schema.String,
  version: Schema.String,
  private: Schema.optional(Schema.Boolean),
  dependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  peerDependencies: Schema.Record(Schema.String, Schema.String),
  exports: Schema.Record(
    Schema.String,
    Schema.Struct({ types: Schema.String })
  ),
});

const decodeManifest = Schema.decodeUnknownSync(
  Schema.fromJsonString(Manifest)
);

/** @param {string} directory The package's directory. */
const readManifest = async (directory) =>
  decodeManifest(await readFile(path.join(directory, "package.json"), "utf-8"));

const { name, version } = await readManifest(root);

const directory = await mkdtemp(
  path.join(tmpdir(), "clankerauth-admin-api-install-")
);

try {
  await installPacked(directory, root, [
    "effect",
    "@gjermundgaraba/effect-actions",
  ]);
  const installed = path.join(directory, "node_modules", name);

  const manifest = await readManifest(installed);

  assert.equal(manifest.version, version);
  assert.equal(manifest.private, undefined);
  assert.deepEqual(
    manifest.dependencies ?? {},
    {},
    "effect and effect-actions must be peers: a second copy would split their types and services"
  );

  for (const peer of ["effect", "@gjermundgaraba/effect-actions"]) {
    const range = manifest.peerDependencies[peer];
    assert.ok(range !== undefined && range !== "", `${peer} must be a peer`);
  }

  await assertDeclarations(installed, manifest.exports);

  await writeFile(
    path.join(directory, "consumer.ts"),
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
`
  );
  await execute(
    process.execPath,
    [
      path.join(root, "node_modules/typescript/bin/tsc"),
      "--noEmit",
      "--strict",
      "--skipLibCheck",
      "--target",
      "ESNext",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      path.join(directory, "consumer.ts"),
    ],
    { cwd: directory }
  );

  await writeFile(
    path.join(directory, "load.mjs"),
    `import { Administration, OwnerHttp } from "${name}";\n` +
      `if (!Administration.some((action) => action.name === "putResource") || !OwnerHttp) process.exit(1);\n`
  );
  await execute(process.execPath, ["load.mjs"], { cwd: directory });

  process.stdout.write(`${name}@${version} installs and loads\n`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
