import { defineConfig } from "vite-plus";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";

export default defineConfig({
  pack: {
    entry: ["src/index.ts", "src/edge.ts"],
    platform: "node",
    target: "node26",
    format: ["esm"],
    dts: false,
    minify: true,
    deps: { resolveDepSubpath: true, alwaysBundle: [/./], onlyBundle: false },
    plugins: [
      {
        name: "bundled-dependency-notices",
        async generateBundle() {
          const packages = new Map<string, string>();

          for (const id of this.getModuleIds()) {
            if (!id.includes("/node_modules/")) continue;
            let directory = dirname(id);

            while (directory.includes("/node_modules/")) {
              const metadata = await readFile(join(directory, "package.json"), "utf8").catch(
                () => undefined,
              );

              if (metadata) {
                // SAFETY: npm package.json declares string name/version; missing fields are rejected below.
                const { name, version } = JSON.parse(metadata) as {
                  name: string;
                  version: string;
                };

                if (name && version) {
                  packages.set(`${name}@${version}`, directory);
                  break;
                }
              }

              directory = dirname(directory);
            }
          }

          const notices = [];

          for (const [name, directory] of [...packages].sort(([a], [b]) => a.localeCompare(b))) {
            const files = (await readdir(directory)).filter((name) =>
              /^(licen[sc]e|notice)(\.|$)/i.test(name),
            );

            if (!files.length) {
              const metadata = await readFile(join(directory, "package.json"), "utf8");
              notices.push(
                `${name}\nNo separate license file is shipped by this package. Published metadata:\n${metadata}\n`,
              );
              continue;
            }

            const text = await Promise.all(
              files.map(
                async (file) => `${file}\n${await readFile(join(directory, file), "utf8")}`,
              ),
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
