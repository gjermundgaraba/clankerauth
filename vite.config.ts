import foldkitRecommended from "@foldkit/oxlint-plugin/recommended.json" with { type: "json" };
import { defineConfig } from "vite-plus";

const foldkitSource = "apps/web/src";

// why: the recommended JSON is untyped, and every level in it is "error" or "off".
const level = (value: string): "error" | "off" => (value === "off" ? "off" : "error");

const levels = (rules: Record<string, string | undefined>) =>
  Object.fromEntries(
    Object.entries(rules).flatMap(([rule, value]) =>
      value === undefined ? [] : [[rule, level(value)] as const],
    ),
  );

const within = (patterns: ReadonlyArray<string> = []) =>
  patterns.map((pattern) => `${foldkitSource}/${pattern}`);

const proseComments = (options: {
  readonly docBlocks?: "all";
  readonly sectionHeaders?: true;
}): ["error", typeof options] => ["error", options];

const commentOverrides = [
  {
    files: ["packages/sdk/src/**", "packages/dev/src/**"],
    rules: { "clankerauth/no-prose-comments": proseComments({ docBlocks: "all" }) },
  },
  {
    files: [`${foldkitSource}/**`],
    rules: { "clankerauth/no-prose-comments": proseComments({ sectionHeaders: true }) },
  },
];

const domainImports = [
  "^effect(/|$)",
  "^@gjermundgaraba/effect-actions/",
  "^@gjermundgaraba/clankerauth-sdk(/|$)",
  "^@clankerauth/admin-api$",
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

const fence = (options: {
  readonly allow?: ReadonlyArray<string>;
  readonly deny?: ReadonlyArray<string>;
}): ["error", typeof options] => ["error", options];

const manualRuns = (options: {
  readonly allow: ReadonlyArray<string>;
}): ["error", typeof options] => ["error", options];

const fenceOverrides = [
  {
    files: ["apps/server/src/**"],
    rules: { "clankerauth/import-fence": fence({ allow: domainImports }) },
  },
  {
    files: ["apps/server/src/http/**"],
    rules: { "clankerauth/import-fence": fence({ allow: httpImports }) },
  },
  {
    files: ["apps/server/src/*.ts", "apps/server/src/platform/**", "apps/server/src/issuer/**"],
    rules: { "clankerauth/import-fence": "off" as const },
  },
  {
    files: ["apps/web/**", "apps/cli/**", "packages/**"],
    rules: {
      "clankerauth/import-fence": fence({
        deny: ["^@clankerauth/server(?!/embed$)", "^apps/server/"],
      }),
    },
  },
  {
    files: ["apps/server/src/issuer/issuer.ts", "apps/server/tests/**", "packages/sdk/tests/**"],
    rules: { "clankerauth/no-manual-effect-run": manualRuns({ allow: ["runPromiseWith"] }) },
  },
  {
    files: [
      "apps/server/src/main.ts",
      "apps/cli/src/main.ts",
      "packages/dev/src/index.ts",
      "**/scripts/**",
    ],
    rules: { "clankerauth/no-manual-effect-run": "off" as const },
  },
  {
    files: ["**/scripts/**"],
    rules: { "clankerauth/import-fence": "off" as const },
  },
];

const foldkitOverrides = [
  { files: [`${foldkitSource}/**/*.ts`], rules: levels(foldkitRecommended.rules) },
  ...foldkitRecommended.overrides.map((override) => ({
    files: within(override.files),
    excludeFiles: within(override.excludeFiles),
    rules: levels(override.rules),
  })),
  // why: the fixtures answer the dashboard Query's fetches with its own Messages, as tests do.
  {
    files: [`${foldkitSource}/page/dashboard/dashboard.fixture.ts`],
    rules: levels({ "foldkit/no-child-message-construction-in-root": "off" }),
  },
];

export default defineConfig({
  fmt: {
    ignorePatterns: [
      ".agent/**",
      ".agents/**",
      ".claude/**",
      ".codex/**",
      ".continue/**",
      ".cursor/**",
      ".gemini/**",
      ".opencode/**",
      ".pi/**",
      ".roo/**",
      ".windsurf/**",
      "tools/oxlint/anti-slop/**",
      // why: the vendored Foldkit reference is read, never checked here.
      "repos/**",
    ],
  },
  lint: {
    options: { typeAware: true, typeCheck: true },
    ignorePatterns: [
      ".agent/**",
      ".agents/**",
      ".claude/**",
      ".codex/**",
      ".continue/**",
      ".cursor/**",
      ".gemini/**",
      ".opencode/**",
      ".pi/**",
      ".roo/**",
      ".windsurf/**",
      "tools/oxlint/anti-slop/**",
      "repos/**",
    ],
    jsPlugins: [
      { name: "foldkit", specifier: "@foldkit/oxlint-plugin" },
      { name: "anti-slop", specifier: "./tools/oxlint/anti-slop/index.ts" },
      {
        name: "anti-slop-effect",
        specifier: "./tools/oxlint/anti-slop/effect/index.ts",
      },
      { name: "clankerauth", specifier: "./tools/oxlint/clankerauth/index.ts" },
    ],
    rules: {
      "oxc/no-accumulating-spread": "error",
      "anti-slop/no-array-filter-map": "error",
      "anti-slop/no-reduce-accumulator-copy": "error",
      "anti-slop/no-chained-type-assertions": "error",
      "anti-slop/no-conditional-empty-object-spread": "error",
      "anti-slop/no-known-value-widening": "error",
      "anti-slop/no-module-mocking": "error",
      "anti-slop/no-object-parameters": "error",
      "anti-slop/no-reflect-apply": "error",
      "anti-slop/no-reflect-get": "error",
      "anti-slop/no-runtime-typeof": ["error", { allowInTypeGuards: true }],
      "anti-slop/no-shape-in-symbol-names": "error",
      "anti-slop/no-unknown-parameters": "error",
      "anti-slop/no-unknown-returns": "error",
      "anti-slop/no-unknown-type-aliases": "error",
      "anti-slop/no-unsafe-dictionary-type": "error",
      "anti-slop/no-widen-then-assert": "error",
      "anti-slop/require-readable-spacing": "error",
      "anti-slop/require-safety-comment-for-type-assertion": "error",
      "anti-slop-effect/no-manual-effect-error-tag": "error",
      "anti-slop-effect/no-manual-tag-comparison": "error",
      "anti-slop-effect/no-manual-tagged-construction": "error",
      "anti-slop-effect/no-service-constructor-imports": "error",
      "anti-slop-effect/prefer-effect-match": "error",
      "clankerauth/no-manual-effect-run": "error",
      "clankerauth/no-prose-comments": "error",
    },
    overrides: [...foldkitOverrides, ...commentOverrides, ...fenceOverrides],
  },
  run: { cache: true },
});
