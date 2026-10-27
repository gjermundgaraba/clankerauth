import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

import { Option, Schema } from "effect";
import { defineConfig } from "vite-plus";

/** The fields a bundled dependency's notice is keyed by. Other `package.json` files are skipped. */
const decodeManifest = Schema.decodeUnknownOption(
  Schema.fromJsonString(
    Schema.Struct({
      name: Schema.NonEmptyString,
      version: Schema.NonEmptyString,
    })
  )
);

export default defineConfig({
  // why: `vp pack` clears dist, and a replayed cache writes nothing, so `edge.d.ts` would vanish.
  run: {
    tasks: {
      build: {
        command:
          "vp pack && tsc -p tsconfig.types.json && node scripts/assets.mjs",
        cache: false,
      },
    },
  },
  pack: {
    entry: ["src/index.ts", "src/edge.ts"],
    platform: "node",
    target: "node26",
    format: ["esm"],
    dts: false,
    minify: true,
    deps: { resolveDepSubpath: true, alwaysBundle: [/./u], onlyBundle: false },
    plugins: [
      {
        name: "bundled-dependency-notices",
        async generateBundle() {
          const packages = new Map<string, string>();

          for (const id of this.getModuleIds()) {
            if (!id.includes("/node_modules/")) {
              continue;
            }

            let directory = path.dirname(id);

            while (directory.includes("/node_modules/")) {
              const manifest = await readFile(
                path.join(directory, "package.json"),
                "utf-8"
              ).then(decodeManifest, () => Option.none());

              if (Option.isSome(manifest)) {
                const { name, version } = manifest.value;
                packages.set(`${name}@${version}`, directory);
                break;
              }

              directory = path.dirname(directory);
            }
          }

          const notices = [];

          for (const [name, directory] of [...packages].toSorted(([a], [b]) =>
            a.localeCompare(b)
          )) {
            const entries = await readdir(directory);

            const files = entries.filter((file) =>
              /^(?:licen[sc]e|notice)(?:\.|$)/iu.test(file)
            );

            if (!files.length) {
              const metadata = await readFile(
                path.join(directory, "package.json"),
                "utf-8"
              );

              notices.push(
                `${name}\nNo separate license file is shipped by this package. Published metadata:\n${metadata}\n`
              );
              continue;
            }

            const text = await Promise.all(
              files.map(
                async (file) =>
                  `${file}\n${await readFile(path.join(directory, file), "utf-8")}`
              )
            );

            notices.push(`${name}\n${text.join("\n")}\n`);
          }

          this.emitFile({
            type: "asset",
            fileName: "THIRD_PARTY_NOTICES.txt",
            source: notices.join("\n---\n\n"),
          });
        },
      },
    ],
  },
});
