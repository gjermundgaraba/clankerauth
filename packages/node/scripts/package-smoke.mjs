import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const root = fileURLToPath(new URL("../", import.meta.url));
const { name, version } = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const directory = await mkdtemp(join(tmpdir(), "clankerauth-node-install-"));
try {
  // pnpm resolves the workspace catalog protocol in the packed manifest; npm would not.
  await execute("pnpm", ["pack", "--pack-destination", directory], { cwd: root });
  const [tarball] = await readdir(directory);
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  await execute(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", join(directory, tarball)],
    { cwd: directory },
  );
  const installed = join(directory, "node_modules", name);
  const manifest = JSON.parse(await readFile(join(installed, "package.json"), "utf8"));
  assert.equal(manifest.version, version);
  assert.deepEqual(Object.keys(manifest.dependencies).sort(), ["jose", "oauth4webapi"]);
  await readFile(join(installed, "dist/index.d.ts"), "utf8");
  const api = await import(pathToFileURL(join(installed, "dist/index.js")).href);
  assert.deepEqual(Object.keys(api).sort(), [
    "AuthError",
    "challenge",
    "createBrowserSession",
    "createVerifier",
    "failureResponse",
    "metadataUrl",
    "protectedResourceMetadata",
  ]);
  const verifier = api.createVerifier({
    issuer: "https://auth.example/api/auth",
    resource: "https://notes.example/api",
  });
  await assert.rejects(verifier.verify(null), (error) => error.code === "unauthorized");
  process.stdout.write(`${name}@${version} installs and loads\n`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
