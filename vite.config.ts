import foldkitRecommended from "@foldkit/oxlint-plugin/recommended.json" with { type: "json" };
import { defineConfig } from "vite-plus";

// The dashboard is a Foldkit application: its source takes Foldkit's recommended rules, with
// the plugin's own per-file overrides (the entry, the tests) scoped to the same files.
const foldkitSource = "apps/web/src";

// The JSON is untyped text; every level in it is "error" or "off".
const level = (value: string): "error" | "off" => (value === "off" ? "off" : "error");

const levels = (rules: Record<string, string | undefined>) =>
  Object.fromEntries(
    Object.entries(rules).flatMap(([rule, value]) =>
      value === undefined ? [] : [[rule, level(value)] as const],
    ),
  );

const within = (patterns: ReadonlyArray<string> = []) =>
  patterns.map((pattern) => `${foldkitSource}/${pattern}`);

const foldkitOverrides = [
  { files: [`${foldkitSource}/**/*.ts`], rules: levels(foldkitRecommended.rules) },
  ...foldkitRecommended.overrides.map((override) => ({
    files: within(override.files),
    excludeFiles: within(override.excludeFiles),
    rules: levels(override.rules),
  })),
  // The dashboard's fixtures read its listing as the tests do, answering the Query's fetches
  // with the Query's own Messages.
  {
    files: [`${foldkitSource}/dashboard/dashboard.fixture.ts`],
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
      // The vendored Foldkit reference is read, never checked here.
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
    },
    overrides: foldkitOverrides,
  },
  run: { cache: true },
});
