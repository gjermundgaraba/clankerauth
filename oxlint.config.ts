import { config } from "@clanker-stuff/oxlint-config";
import foldkit from "@foldkit/oxlint-plugin";

export const ignorePatterns = [".agents/", "repos/"];

const dashboard = "apps/web/src";
const { recommended } = foldkit.configs;

const withinDashboard = (patterns: readonly string[] = []) =>
  patterns.map((pattern) => `${dashboard}/${pattern}`);

const domainImports = [
  "^effect(/|$)",
  "^@gjermundgaraba/effect-actions/",
  "^@gjermundgaraba/clankerauth-sdk(/|$)",
  "^@gjermundgaraba/clankerauth-admin-api$",
  "^apps/server/src/(?!http/)[^/]+/",
];

const httpImports = [
  ...domainImports,
  "^apps/server/src/http/",
  "^apps/server/package\\.json$",
  "^@effect/platform-node$",
  "^@clankerauth/web/document-paths$",
  "^node:(path|url)$",
];

export default config({
  testBlocks: ["it.effect", "it.live"],
  expectBlocks: ["it.effect.each", "it.live.each"],
  assertFunctions: ["scene", "story"],
  ignorePatterns,
  jsPlugins: [
    ...recommended.jsPlugins,
    { name: "clankerauth", specifier: "./tools/oxlint/clankerauth/index.ts" },
  ],
  overrides: [
    {
      env: { browser: true, node: false },
      files: [`${dashboard}/**`, "apps/server/scripts/browser-oauth-client.ts"],
    },
    { files: [`${dashboard}/**/*.ts`], rules: recommended.rules },
    ...recommended.overrides.map((override) => ({
      ...override,
      excludeFiles: withinDashboard(override.excludeFiles),
      files: withinDashboard(override.files),
    })),
    {
      files: [`${dashboard}/**/*scene.test.ts`],
      plugins: ["vitest"],
      rules: { "vitest/prefer-importing-vitest-globals": "off" },
    },
    {
      files: [`${dashboard}/page/dashboard/dashboard.fixture.ts`],
      rules: { "foldkit/no-child-message-construction-in-root": "off" },
    },
    {
      files: ["apps/server/src/**"],
      rules: {
        "clankerauth/import-fence": ["error", { allow: domainImports }],
      },
    },
    {
      files: ["apps/server/src/http/**"],
      rules: { "clankerauth/import-fence": ["error", { allow: httpImports }] },
    },
    {
      files: [
        "apps/server/src/*.ts",
        "apps/server/src/platform/**",
        "apps/server/src/issuer/**",
      ],
      rules: { "clankerauth/import-fence": "off" },
    },
    {
      files: ["apps/web/**", "apps/cli/**", "packages/**"],
      rules: {
        "clankerauth/import-fence": [
          "error",
          { deny: ["^@clankerauth/server(?!/embed$)", "^apps/server/"] },
        ],
      },
    },
    { files: ["**/scripts/**"], rules: { "clankerauth/import-fence": "off" } },
    { files: ["**"], rules: { "clankerauth/no-manual-effect-run": "error" } },
    {
      files: [
        "apps/server/src/issuer/issuer.ts",
        "apps/server/tests/**",
        "packages/sdk/tests/**",
      ],
      rules: {
        "clankerauth/no-manual-effect-run": [
          "error",
          { allow: ["runPromiseWith"] },
        ],
      },
    },
    {
      files: [
        "apps/server/src/main.ts",
        "apps/cli/src/main.ts",
        "packages/dev/src/index.ts",
        "**/scripts/**",
      ],
      rules: { "clankerauth/no-manual-effect-run": "off" },
    },
    {
      files: ["scripts/package-install.mjs"],
      rules: { "typescript/strict-void-return": "off" },
    },
    {
      files: ["packages/dev/tests/lifecycle.test.mts"],
      plugins: ["vitest"],
      rules: {
        "vitest/no-import-node-test": "off",
        "vitest/prefer-importing-vitest-globals": "off",
      },
    },
    {
      files: [
        "packages/sdk/src/index.ts",
        "packages/sdk/src/effect-actions.ts",
      ],
      rules: { "oxc/no-barrel-file": "off" },
    },
    {
      files: ["packages/sdk/src/credentials.ts"],
      rules: { "typescript/no-deprecated": "off" },
    },
  ],
});
