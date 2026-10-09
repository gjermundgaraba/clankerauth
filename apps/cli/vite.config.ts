import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    // The administration contract is a workspace package, so it is bundled; Effect and
    // effect-actions are dependencies, installed beside it.
    deps: { resolveDepSubpath: true },
    entry: ["src/main.ts"],
    platform: "node",
    format: ["esm"],
    outExtensions: () => ({ js: ".mjs" }),
    dts: false,
  },
  // The tests run the packed binary, which `test` builds first, each against an issuer of
  // its own: a random order keeps them independent.
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 30000,
    sequence: { shuffle: { tests: true } },
  },
});
