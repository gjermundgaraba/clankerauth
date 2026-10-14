import { defineConfig } from "vite-plus";

export default defineConfig({
  // why: the task cache does not track the native TypeScript 7 compiler's file reads.
  run: { tasks: { build: { command: "tsc -p tsconfig.build.json", cache: false } } },
  test: { include: ["tests/**/*.test.ts"], testTimeout: 30000 },
});
