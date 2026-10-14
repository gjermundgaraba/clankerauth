import { eslintCompatPlugin } from "vite-plus/lint/plugins";

import { importFenceRule } from "./rules/import-fence.ts";
import { noManualEffectRunRule } from "./rules/no-manual-effect-run.ts";
import { noProseCommentsRule } from "./rules/no-prose-comments.ts";

const clankerauthPlugin = eslintCompatPlugin({
  meta: { name: "clankerauth" },
  rules: {
    "import-fence": importFenceRule,
    "no-manual-effect-run": noManualEffectRunRule,
    "no-prose-comments": noProseCommentsRule,
  },
});

export default clankerauthPlugin;
