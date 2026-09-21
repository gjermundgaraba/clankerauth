import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);

const root = fileURLToPath(new URL("../", import.meta.url));

const serverRequire = createRequire(new URL("../../../apps/server/package.json", import.meta.url));

const { name, version } = JSON.parse(await readFile(join(root, "package.json"), "utf8"));

const directory = await mkdtemp(join(tmpdir(), "clankerauth-dev-install-"));

try {
  await execute("npm", ["pack", "--pack-destination", directory], { cwd: root });
  const [tarball] = await readdir(directory);
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  await execute(
    "npm",
    [
      "install",
      "--offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(directory, tarball),
    ],
    { cwd: directory },
  );
  const installed = join(directory, "node_modules", name);
  const manifest = JSON.parse(await readFile(join(installed, "package.json"), "utf8"));
  assert.equal(manifest.version, version);
  assert.deepEqual(manifest.dependencies ?? {}, {});
  const notices = await readFile(join(installed, "dist/THIRD_PARTY_NOTICES.txt"), "utf8");
  const headings = new Set(notices.split("\n---\n\n").map((section) => section.split("\n")[0]));

  for (const provider of ["@better-auth/api-key", "@better-auth/oauth-provider"]) {
    // Providers export their dist entry, but not their package manifest.
    const manifestPath = join(dirname(serverRequire.resolve(provider)), "../package.json");
    const { version } = JSON.parse(await readFile(manifestPath, "utf8"));
    const heading = `${provider}@${version}`;
    assert.ok(headings.has(heading), `Missing bundled dependency notice: ${heading}`);
  }

  const test = (await readFile(join(root, "tests/lifecycle.test.mjs"), "utf8"))
    .replace('"../dist/index.mjs"', JSON.stringify(name))
    .replace('"../dist/edge.mjs"', JSON.stringify(`${name}/edge`))
    .replace('"../dist/testing.mjs"', JSON.stringify(`${name}/testing`));

  await writeFile(join(directory, "installed.test.mjs"), test);

  const result = await execute(process.execPath, ["--test", "installed.test.mjs"], {
    cwd: directory,
    timeout: 60000,
  });

  process.stdout.write(result.stdout);
} finally {
  await rm(directory, { recursive: true, force: true });
}
