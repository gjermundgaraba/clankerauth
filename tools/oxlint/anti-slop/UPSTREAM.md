# Vendored anti-slop Oxlint plugin

Source: [dmmulroy/anti-slop](https://github.com/dmmulroy/anti-slop), commit `c44ef22ca116d0ba62a3ff663a0bd13a3f3fa40b`.

Installed from the `install-anti-slop` skill bundle (`assets/anti-slop/`), which vendors that upstream revision.

## Installed paths

- Generic plugin: `tools/oxlint/anti-slop/index.ts`
- Effect plugin: `tools/oxlint/anti-slop/effect/index.ts`
- Nested ESLint Stylistic readability vendor: `tools/oxlint/anti-slop/vendor/eslint-stylistic/` (see its `UPSTREAM.md` and `LICENSE`)

## Configuration

Registered in root `vite.config.ts` under `lint.jsPlugins`, with matching `lint.ignorePatterns` and `fmt.ignorePatterns`. Generic rules, `oxc/no-accumulating-spread`, and Effect rules are enabled at `"error"` because this repository declares a direct `effect` dependency.

## Dependencies

- Resolved `oxlint` via `vite-plus`: `1.82.0`
- Direct `devDependency`: `@oxlint/plugins@1.82.0` (pinned to match oxlint)

## Intentional deviations

- Plugin assets: none from the skill bundle.
- Lint policy: `anti-slop/no-runtime-typeof` is configured as
  `["error", { allowInTypeGuards: true }]` so boundary type predicates may use
  idiomatic `typeof`. Typeof outside type guards remains an error.

- Boundary policy: narrow, explained inline exceptions permit the persisted-row
  decoder in `apps/server/src/resources.ts` to accept `unknown`, and permit
  `apps/server/src/onboarding.ts` to import `makeSql`. The latter is an adapter
  over the owned database, not a contextual service constructor. The rule still
  uses a name-based heuristic; it does not prove service ownership. We deliberately
  avoid adding another naming heuristic or a cross-module type analyzer.
- Wire assertions: encode the expected tagged error, then compare the raw response.
  Decoding actual responses strips excess properties and can hide leaks. Tests
  are not blanket-exempt from tagged-construction rules. Independent protocol
  fixtures may use a documented, narrow exception when encoding the expected
  value would make the contract assertion circular.
- `packages/sdk` is now Effect-native, so Effect rules remain enabled there.

## Regression tests

Run `vp run test:lint`. This runs the installed Vite+/Oxlint runner against
temporary fixtures under `apps/server` (removed in `finally`), plus the actual
production boundary exceptions. It verifies rejected unknown inputs and aliased
constructor imports, accepted documented boundaries, and constructor/encoder wire
expectations. Rule activation and file ignores come from repository configuration,
without CLI overrides. The expected rule name only checks diagnostics; it does not
enable the rule. Unused suppression directives are errors.

The test command runs as part of `vp run check` and therefore `vp run ready`.
`apps/server/tests/error-wire.test.ts` also demonstrates why excess fields must
be tested on raw responses. No vendored rule implementation has been changed.
