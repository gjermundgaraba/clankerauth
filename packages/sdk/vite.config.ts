import { defineConfig } from "vite-plus";

export default defineConfig({
  // Native TypeScript 7 compiler reads are not tracked by the current task cache.
  run: { tasks: { build: { command: "tsc -p tsconfig.build.json", cache: false } } },
  test: { include: ["tests/**/*.test.ts"], testTimeout: 30000 },
});
