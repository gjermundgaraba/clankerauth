import { defineConfig } from "vite-plus";

export default defineConfig({
  // why: the task cache does not track the native TypeScript 7 compiler's reads.
  run: { tasks: { build: { command: "tsc -p tsconfig.json", cache: false } } },
});
