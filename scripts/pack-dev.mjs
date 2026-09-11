import { execFile } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const output = fileURLToPath(new URL("../dist/", import.meta.url));
await mkdir(output, { recursive: true });
const result = await promisify(execFile)("npm", ["pack", "--pack-destination", output], {
  cwd: fileURLToPath(new URL("../packages/dev/", import.meta.url)),
});
process.stdout.write(result.stdout);
