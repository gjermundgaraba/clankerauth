import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const { version } = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const tarball = fileURLToPath(
  new URL(`../../../dist/clankerauth-dev-${version}.tgz`, import.meta.url),
);
const directory = await mkdtemp(join(tmpdir(), "clankerauth-dev-install-"));
try {
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  await execute(
    "npm",
    ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
    { cwd: directory },
  );
  const installed = JSON.parse(
    await readFile(join(directory, "node_modules/@clankerauth/dev/package.json"), "utf8"),
  );
  assert.equal(installed.version, version);
  assert.deepEqual(installed.dependencies ?? {}, {});
  const notices = await readFile(
    join(directory, "node_modules/@clankerauth/dev/dist/THIRD_PARTY_NOTICES.txt"),
    "utf8",
  );
  assert.match(notices, /@better-auth\/api-key@1\.7\.3/);
  assert.match(notices, /@better-auth\/oauth-provider@1\.7\.3/);
  const test = (
    await readFile(new URL("../tests/lifecycle.test.mjs", import.meta.url), "utf8")
  ).replace('"../dist/index.mjs"', '"@clankerauth/dev"');
  await writeFile(join(directory, "installed.test.mjs"), test);
  const result = await execute(process.execPath, ["--test", "installed.test.mjs"], {
    cwd: directory,
    timeout: 60000,
  });
  process.stdout.write(result.stdout);
  console.log(
    "Standalone npm tarball installation passed without workspace or runtime dependencies.",
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
