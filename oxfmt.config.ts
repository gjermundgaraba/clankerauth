import ultracite from "ultracite/oxfmt";
import type { OxfmtConfig } from "vite-plus/fmt";

import { ignorePatterns } from "./oxlint.config.ts";

export default {
  ...ultracite,
  ignorePatterns: [
    ...(ultracite.ignorePatterns ?? []),
    ...ignorePatterns,
    "AGENTS.md",
  ],
} satisfies OxfmtConfig;
