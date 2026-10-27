import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    deps: { resolveDepSubpath: true },
    entry: ["src/main.ts"],
    platform: "node",
    format: ["esm"],
    outExtensions: () => ({ js: ".mjs" }),
    dts: false,
  },
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 30_000,
    sequence: { shuffle: { tests: true } },
  },
});
