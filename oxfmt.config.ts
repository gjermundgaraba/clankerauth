import { defineConfig } from "oxfmt";
import ultracite from "ultracite/oxfmt";

import { ignorePatterns } from "./oxlint.config.ts";

export default defineConfig({
  ...ultracite,
  ignorePatterns: [
    ...(ultracite.ignorePatterns ?? []),
    ...ignorePatterns,
    // `vp config` writes the Vite+ block of AGENTS.md on every install; Ultracite would rewrap it.
    "AGENTS.md",
  ],
});
