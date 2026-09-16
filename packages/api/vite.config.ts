import { defineConfig } from "vite-plus";

export default defineConfig({
  // Native TypeScript 7 compiler reads are not tracked by the current task cache.
  run: { tasks: { build: { command: "tsc -p tsconfig.json", cache: false } } },
});
