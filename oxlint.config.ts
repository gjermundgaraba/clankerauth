import { recommended as effect } from "@effect/tsgo/oxlint-presets";
import foldkit from "@foldkit/oxlint-plugin";
import { defineConfig } from "oxlint";
import type { DummyRuleMap, OxlintOverride } from "oxlint";
import antiSlop from "ultracite/oxlint/anti-slop";
import core from "ultracite/oxlint/core";
import vitest from "ultracite/oxlint/vitest";

// The shared Ultracite exceptions. Every Effect/Vite+ repository carries this block verbatim, so
// a grep finds every copy; only the test-block and assertion-function name lists vary. Each rule
// here conflicts with an Effect idiom or with a contract the code must keep. Changing the block
// needs maintainer approval, and changes every copy.
// The files Ultracite's vitest preset treats as tests, so its rules and these relaxations agree.
const testFiles = [
  "**/*.{test,spec,test-d,spec-d}.{ts,tsx,js,jsx,mts,cts,mjs,cjs}",
  "**/__tests__/**/*.{ts,tsx,js,jsx,mts,cts,mjs,cjs}",
];

const sharedRules: DummyRuleMap = {
  // Key order carries meaning: wire formats, hashes, CLI flags, tool schemas, UI order.
  "sort-keys": "off",
  // A module holds several tagged errors or services, which are classes.
  "max-classes-per-file": "off",
  // A loop awaits in order where order, back-pressure or one-at-a-time I/O matters.
  "no-await-in-loop": "off",
  // With `promise-function-async`, it forces `await Promise.resolve(x)` into thin async wrappers.
  "require-await": "off",
  // `return yield*` in a generator reads as an inconsistent return.
  "typescript/consistent-return": "off",
  // A module may call a function or class declared further down, and types are hoisted; a
  // value used before its declaration is still an error.
  "no-use-before-define": [
    "error",
    { classes: false, functions: false, ignoreTypeReferences: true },
  ],
  // Metrics, not defects: splitting to satisfy them scatters one decision across helpers.
  complexity: "off",
  "max-nested-callbacks": "off",
  // Hashes, file modes and binary formats are bitwise by nature.
  "no-bitwise": "off",
  // Effect modules are PascalCase (`Schema.ts`); everything else is kebab-case.
  "unicorn/filename-case": [
    "error",
    { cases: { kebabCase: true, pascalCase: true } },
  ],
  // Optional DTO fields belong in their construction expression.
  "anti-slop/no-conditional-empty-object-spread": "off",
  // Generators passed to Effect.gen and Effect.fn are named by their span, not the function.
  "func-names": ["error", "as-needed", { generators: "never" }],
  // A schema and its type share a name; tsc rejects real redeclarations.
  "no-redeclare": "off",
  // `Effect.catch` is not a promise chain.
  "promise/prefer-await-to-then": "off",
  // Effect handlers are typed functions, not error-first callbacks: the rule flags every
  // `Effect.catch((error) => ...)`, the name `unicorn/catch-error-name` demands.
  "promise/prefer-await-to-callbacks": "off",
  // `readonly string[]`, but `ReadonlyArray<Html | string>` over `readonly (Html | string)[]`.
  "typescript/array-type": [
    "error",
    { default: "array-simple", readonly: "array-simple" },
  ],
  // Effect's data-first `map(self, f)` and `filter(self, f)` take no thisArg.
  "unicorn/no-array-method-this-argument": "off",
  // Effect APIs take `undefined` as a value, as in `Deferred.succeed(done, undefined)`.
  "unicorn/no-useless-undefined": ["error", { checkArguments: false }],
  // `Schema.TaggedError<X>()` builds an error class; it throws nothing.
  "unicorn/throw-new-error": "off",
  // Notices for every unstable Effect API bury the warnings that matter.
  "effecttsgo/unstable-api-usage": "off",
};

const sharedTestOverride: OxlintOverride = {
  files: testFiles,
  // Naming the plugin lets the override reach its rules.
  plugins: ["vitest"],
  rules: {
    // `@effect/vitest`'s test functions are test blocks, and the repository's assertion helpers
    // (Foldkit's `scene`/`story` among them, where used) assert. List the names the repository uses.
    "vitest/no-standalone-expect": [
      "error",
      {
        additionalTestBlockFunctions: [
          "it.effect",
          "it.effect.each",
          "it.live",
          "it.live.each",
        ],
      },
    ],
    "vitest/expect-expect": [
      "error",
      {
        additionalTestBlockFunctions: ["it.effect", "it.live"],
        assertFunctionNames: [
          "expect",
          "expectTypeOf",
          "assert",
          "assert.*",
          "scene",
          "story",
        ],
      },
    ],
    // An `Effect.fn` export's runtime name is empty, so `describe(fn)` reports `<anonymous>`; the
    // rule also takes namespace imports for functions. Titles are strings.
    "vitest/prefer-describe-function-title": "off",
    // A test writes `find(...)!` for what it asserts exists.
    "typescript/no-non-null-assertion": "off",
    // Each value gets its own `expect`, with a message where the value alone would not explain a failure.
    "vitest/max-expects": "off",
    "vitest/valid-expect": ["error", { maxArgs: 2 }],
    // `toBe(true)` asserts a boolean; `toBeTruthy()` accepts any truthy value.
    "vitest/prefer-to-be-truthy": "off",
    "vitest/prefer-to-be-falsy": "off",
    // Tests feed hostile and literal input on purpose.
    "no-script-url": "off",
    "no-template-curly-in-string": "off",
    // Replaces Ultracite's `no-module-mocking`, which misses `vi` from `vite-plus/test`.
    "vitest/no-restricted-vi-methods": [
      "error",
      {
        doMock:
          "Replace dependencies through Layers or real interfaces, not module mocks.",
        mock: "Replace dependencies through Layers or real interfaces, not module mocks.",
      },
    ],
  },
};

// Vendored references and the agent skills are read, never checked.
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

export default defineConfig({
  env: { node: true },
  extends: [core, antiSlop, vitest, effect],
  ignorePatterns: [...(core.ignorePatterns ?? []), ...ignorePatterns],
  jsPlugins: [
    ...recommended.jsPlugins,
    { name: "clankerauth", specifier: "./tools/oxlint/clankerauth/index.ts" },
  ],
  options: {
    denyWarnings: true,
    reportUnusedDisableDirectives: "deny",
    typeAware: true,
    typeCheck: true,
  },
  overrides: [
    sharedTestOverride,
    // The dashboard, and the page the browser OAuth smoke serves, run in a browser.
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
    // A Scene test (`scene.test.ts` or `<page>.scene.test.ts`) asserts with `expect` from
    // `foldkit/scene`, which the rule takes for Vitest's global; its fix imports Vitest's `expect`
    // beside it, a duplicate binding.
    {
      files: [`${dashboard}/**/*scene.test.ts`],
      plugins: ["vitest"],
      rules: { "vitest/prefer-importing-vitest-globals": "off" },
    },
    // The fixtures answer the dashboard Query's fetches with its own Messages, as tests do.
    {
      files: [`${dashboard}/page/dashboard/dashboard.fixture.ts`],
      rules: { "foldkit/no-child-message-construction-in-root": "off" },
    },
    // Each server domain imports Effect, the contracts and other domains; http/ adds its own
    // list; only the root files, platform/ and issuer/ take technology. Outside the server,
    // only its embed entry is importable.
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
    // Effect runs by hand only in entries, scripts and bridges foreign code calls; tests and
    // the Better Auth bridge use runPromiseWith.
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
    // The SDK smoke imports the just-packed tarball from a temporary install, so its exports
    // are untyped to the checker.
    {
      files: ["packages/sdk/scripts/package-smoke.mjs"],
      rules: {
        "typescript/no-unsafe-assignment": "off",
        "typescript/no-unsafe-call": "off",
        "typescript/no-unsafe-member-access": "off",
        "typescript/no-unsafe-return": "off",
      },
    },
    // The rule reads `promisify(execFile)` against `execFile`'s callback overload, while tsc
    // resolves Node's `{ stdout, stderr }` promise overload.
    {
      files: ["scripts/package-install.mjs"],
      rules: { "typescript/strict-void-return": "off" },
    },
    // The packed-package smoke runs this suite with Node's test runner in a clean install of the
    // tarball, where Vitest is not installed.
    {
      files: ["packages/dev/tests/lifecycle.test.mts"],
      plugins: ["vitest"],
      rules: {
        "vitest/no-import-node-test": "off",
        "vitest/prefer-importing-vitest-globals": "off",
      },
    },
    // Published surface: each override below keeps a package's exported API, or what it throws,
    // as published.
    // The SDK's entry points re-export its modules as the namespaces `package.json` publishes.
    {
      files: [
        "packages/sdk/src/index.ts",
        "packages/sdk/src/effect-actions.ts",
      ],
      rules: { "oxc/no-barrel-file": "off" },
    },
    // `ProviderUnavailable` keeps its public constructor, which takes a cause it does not encode.
    {
      files: ["packages/sdk/src/errors.ts"],
      rules: { "effecttsgo/overridden-schema-constructor": "off" },
    },
    // `Credentials.list()` is an exported function of the published `/credentials` entry; as a
    // value, every `list()` call breaks. Its sign-in reaches an `http:` loopback issuer, such as
    // the dev package's, only through oauth4webapi's deprecated `allowInsecureRequests`.
    {
      files: ["packages/sdk/src/credentials.ts"],
      rules: {
        "effecttsgo/lazy-effect": "off",
        "typescript/no-deprecated": "off",
      },
    },
    // The published helpers throw `Error` when a port cannot be bound; callers see the class.
    {
      files: ["packages/sdk/src/testing.ts", "packages/dev/src/edge.ts"],
      rules: { "unicorn/prefer-type-error": "off" },
    },
    // The published declarations use method signatures, which callers' fakes are checked against
    // bivariantly; property signatures would reject some that assign today.
    {
      files: ["packages/dev/src/types.d.ts"],
      rules: { "typescript/method-signature-style": "off" },
    },
    // The published `startDisposableIssuer` rejects with these plain `Error`s; a tagged class
    // changes the class its callers receive.
    {
      files: ["packages/dev/src/index.ts"],
      rules: { "effecttsgo/global-error-in-effect-failure": "off" },
    },
  ],
  rules: { ...sharedRules },
});
