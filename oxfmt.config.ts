import { defineConfig } from "oxfmt";
import ultracite from "ultracite/oxfmt";

import { ignorePatterns } from "./oxlint.config.ts";

export default defineConfig({
  ...ultracite,
  ignorePatterns: [
    ...(ultracite.ignorePatterns ?? []),
    ...ignorePatterns,
    "AGENTS.md",
  ],
});
