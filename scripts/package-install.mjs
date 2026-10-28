import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

export const execute = promisify(execFile);

/**
 * @param {string} installed
 * @param {Readonly<Record<string, { readonly types: string }>>} exports
 */
export const assertDeclarations = async (installed, exports) => {
  for (const [entry, target] of Object.entries(exports)) {
    const declarations = await readFile(
      path.join(installed, target.types),
      "utf-8"
    );

    assert.ok(
      declarations.length > 0,
      `Entry point ships no declarations: ${entry}`
    );
  }
};

/**
 * @param {string} directory
 * @param {string} root
 * @param {string} dependency
 */
export const packDependency = async (directory, root, dependency) => {
  const { stdout } = await execute(
    "npm",
    [
      "pack",
      "--ignore-scripts",
      "--pack-destination",
      directory,
      await realpath(path.join(root, "node_modules", dependency)),
    ],
    { cwd: directory }
  );

  return path.join(directory, stdout.trim());
};

/**
 * @param {string} directory
 * @param {string} root
 * @param {readonly string[]} peers
 */
export const installPacked = async (directory, root, peers) => {
  await execute("pnpm", ["pack", "--pack-destination", directory], {
    cwd: root,
  });

  const files = await readdir(directory);
  const tarball = files.find((file) => file.endsWith(".tgz"));

  if (tarball === undefined) {
    throw new Error(`pnpm pack wrote no tarball to ${directory}`);
  }

  await writeFile(
    path.join(directory, "package.json"),
    JSON.stringify({ private: true, type: "module" })
  );

  const packedPeers = [];

  for (const peer of peers) {
    packedPeers.push(await packDependency(directory, root, peer));
  }

  await execute(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      path.join(directory, tarball),
      ...packedPeers,
    ],
    { cwd: directory }
  );
};
