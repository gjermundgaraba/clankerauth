import { execFile } from "node:child_process";
import { readdir, realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);

export const packDependency = async (directory, root, dependency) => {
  const { stdout } = await execute(
    "npm",
    [
      "pack",
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      directory,
      await realpath(join(root, "node_modules", dependency)),
    ],
    { cwd: directory },
  );

  // why: npm prints the packed packages as an array, or in newer versions as an object keyed by name.
  const [packed] = Object.values(JSON.parse(stdout));

  return join(directory, packed.filename);
};

export const installPacked = async (directory, root, peers) => {
  // why: pnpm pack resolves the workspace catalog protocol in the manifest; npm pack would not.
  await execute("pnpm", ["pack", "--pack-destination", directory], { cwd: root });
  const tarball = (await readdir(directory)).find((file) => file.endsWith(".tgz"));

  if (tarball === undefined) throw new Error(`pnpm pack wrote no tarball to ${directory}`);
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );

  const packedPeers = [];

  for (const peer of peers) packedPeers.push(await packDependency(directory, root, peer));

  await execute(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(directory, tarball),
      ...packedPeers,
    ],
    { cwd: directory },
  );
};
