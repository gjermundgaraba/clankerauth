import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vite-plus/test";

const root = fileURLToPath(new URL("../../../../", import.meta.url));

const diagnostic = /^[^:]+:(?<line>\d+):\d+: .* \[\w+\/(?<code>[^\]]+)\]$/u;

const summary = /^\d+ problems?$/u;

const expectEveryLineParsed = (lines: readonly string[], stderr: string) => {
  expect(
    lines.filter((line) => !diagnostic.test(line) && !summary.test(line)),
    stderr
  ).toStrictEqual([]);
};

const ruleLines = async (
  rule: string,
  folder: string,
  source: string,
  cwd = root
) => {
  const directory = await mkdtemp(path.join(root, folder, "lint-fixture-"));

  try {
    await writeFile(path.join(directory, "fixture.ts"), source);

    const result = spawnSync(
      "vp",
      ["lint", path.join(directory, "fixture.ts"), "--format", "unix"],
      { cwd, encoding: "utf-8", timeout: 30_000 }
    );

    expect(result.error).toBeUndefined();
    expect([0, 1], result.stderr).toContain(result.status);

    const lines = result.stdout.split("\n").filter((line) => line !== "");

    expectEveryLineParsed(lines, result.stderr);

    return lines
      .flatMap((line) => {
        const { code, line: number } = diagnostic.exec(line)?.groups ?? {};

        return code === `clankerauth(${rule})` ? [Number(number)] : [];
      })
      .toSorted((a, b) => a - b);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
};

const imports = (...specifiers: string[]) =>
  `${specifiers.map((specifier) => `export * from "${specifier}";`).join("\n\n")}\n`;

describe("clankerauth lint policy", () => {
  it("a domain folder imports Effect, the contracts and other domains, never a vendor or http/", async () => {
    await expect(
      ruleLines(
        "import-fence",
        "apps/server/src/clients",
        `${imports(
          "effect",
          "@gjermundgaraba/clankerauth-admin-api",
          "../../platform/sqlite.ts",
          "kysely",
          "node:crypto",
          "../../http/actions.ts"
        )}\nexport const later = (name: string) => import(name);\n`
      )
    ).resolves.toStrictEqual([7, 9, 11, 13]);
  });

  it("platform/ and issuer/ take technology, and http/ its own list", async () => {
    await expect(
      ruleLines("import-fence", "apps/server/src/platform", imports("kysely"))
    ).resolves.toStrictEqual([]);
    await expect(
      ruleLines(
        "import-fence",
        "apps/server/src/issuer",
        imports("better-auth/crypto")
      )
    ).resolves.toStrictEqual([]);
    await expect(
      ruleLines(
        "import-fence",
        "apps/server/src/http",
        imports("node:path", "kysely")
      )
    ).resolves.toStrictEqual([3]);
  });

  it("outside the server, only its embed entry is importable", async () => {
    await expect(
      ruleLines(
        "import-fence",
        "packages/dev/src",
        imports(
          "@clankerauth/server/embed",
          "@clankerauth/server/src/services.ts",
          "../../../../apps/server/src/services.ts"
        )
      )
    ).resolves.toStrictEqual([3, 5]);
  });

  it("the fence judges the same from inside a package as from the root", async () => {
    await expect(
      ruleLines(
        "import-fence",
        "apps/server/src/clients",
        imports("../../platform/sqlite.ts", "kysely"),
        path.join(root, "apps/server")
      )
    ).resolves.toStrictEqual([3]);
    await expect(
      ruleLines(
        "import-fence",
        "packages/dev/src",
        imports("../../../../apps/server/src/services.ts"),
        path.join(root, "packages/dev")
      )
    ).resolves.toStrictEqual([1]);
  });

  it("Effect runs by hand only in entries and bridges, and tests bridge with runPromiseWith", async () => {
    const runs = [
      'import { Effect } from "effect";',
      "",
      "export const a = Effect.runPromise(Effect.void);",
      "",
      "export const b = Effect.runPromiseWith(Effect.context<never>)(Effect.void);",
    ].join("\n");

    await expect(
      ruleLines("no-manual-effect-run", "apps/server/src/clients", runs)
    ).resolves.toStrictEqual([3, 5]);
    await expect(
      ruleLines("no-manual-effect-run", "apps/server/tests", runs)
    ).resolves.toStrictEqual([3]);
  });
});
