import { eslintCompatPlugin } from "vite-plus/lint/plugins";

import { noProseCommentsRule } from "./rules/no-prose-comments.ts";

const clankerauthPlugin = eslintCompatPlugin({
  meta: { name: "clankerauth" },
  rules: {
    "no-prose-comments": noProseCommentsRule,
  },
});

export default clankerauthPlugin;
