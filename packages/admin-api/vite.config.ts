import { defineConfig } from "vite-plus";

export default defineConfig({
  run: { tasks: { build: { command: "tsc -p tsconfig.json", cache: false } } },
});
