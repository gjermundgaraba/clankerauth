import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: ["src/main.ts"],
    platform: "node",
    format: ["esm"],
    dts: false,
  },
  test: { include: ["tests/**/*.test.ts"], testTimeout: 30000 },
});
