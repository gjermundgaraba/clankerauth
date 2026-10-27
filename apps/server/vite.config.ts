import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    deps: {
      resolveDepSubpath: true,
      alwaysBundle: ["@clankerauth/web/document-paths"],
    },
    entry: ["src/main.ts"],
    platform: "node",
    format: ["esm"],
    dts: false,
  },
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 30_000,
    restoreMocks: true,
  },
});
