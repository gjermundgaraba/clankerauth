// Exercise clanker-okf's shipped authentication boundary with the official MCP SDK.
// Dependencies are supplied explicitly; this runner never installs packages or loads .env.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

assert.ok(
  process.argv[2] && process.argv[3],
  "Usage: pnpm test:interop <clanker-okf checkout> <MCP SDK fixture directory>",
);
assert.equal(
  typeof globalThis.Temporal,
  "object",
  "clanker-okf requires a Temporal-enabled Node runtime; run this script with that Node binary",
);
const okf = resolve(process.argv[2]);
const sdk = resolve(process.argv[3]);
const auth = fileURLToPath(new URL("../../..", import.meta.url));
const child = spawn(
  process.execPath,
  [
    "--import",
    join(sdk, "node_modules/tsx/dist/loader.mjs"),
    join(auth, "apps/server/scripts/oauth-interop.mjs"),
    okf,
    sdk,
  ],
  { cwd: okf, stdio: "inherit" },
);
const [code, signal] = await once(child, "exit");
assert.equal(signal, null, `Interop terminated by ${signal}`);
process.exitCode = code ?? 1;
