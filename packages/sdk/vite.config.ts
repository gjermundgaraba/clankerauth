import { defineConfig } from "vite-plus";

export default defineConfig({
  run: {
    tasks: { build: { command: "tsc -p tsconfig.build.json", cache: false } },
  },
  test: { include: ["tests/**/*.test.ts"], testTimeout: 30_000 },
});
