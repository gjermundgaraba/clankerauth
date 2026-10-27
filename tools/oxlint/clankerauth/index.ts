import { eslintCompatPlugin } from "vite-plus/lint/plugins";

import { importFenceRule } from "./rules/import-fence.ts";
import { noManualEffectRunRule } from "./rules/no-manual-effect-run.ts";

const clankerauthPlugin = eslintCompatPlugin({
  meta: { name: "clankerauth" },
  rules: {
    "import-fence": importFenceRule,
    "no-manual-effect-run": noManualEffectRunRule,
  },
});

export default clankerauthPlugin;
