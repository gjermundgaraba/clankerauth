import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

export const execute = promisify(execFile);

/**
 * Fails unless every entry point of an installed package ships declarations.
 * @param {string} installed The installed package's directory.
 * @param {Readonly<Record<string, { readonly types: string }>>} exports Its manifest's `exports`.
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
 * @param {string} directory The directory to pack into.
 * @param {string} root The workspace package whose dependency to pack.
 * @param {string} dependency The dependency's package name.
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

  // why: npm prints the tarball's filename alone on stdout, its notices on stderr.
  return path.join(directory, stdout.trim());
};

/**
 * @param {string} directory The directory to install into.
 * @param {string} root The workspace package to pack and install.
 * @param {readonly string[]} peers The peer dependencies to pack beside it.
 */
export const installPacked = async (directory, root, peers) => {
  // why: pnpm pack resolves the workspace catalog protocol in the manifest; npm pack would not.
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
