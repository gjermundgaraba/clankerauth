<!--VITE PLUS START-->

# Using Vite+, the Unified Toolchain for the Web

This project is using Vite+, a unified toolchain built on top of Vite, Rolldown, Vitest, tsdown, Oxlint, Oxfmt, and Vite Task. Vite+ wraps runtime management, package management, and frontend tooling in a single global CLI called `vp`. Vite+ is distinct from Vite, and it invokes Vite through `vp dev` and `vp build`. Run `vp help` to print a list of commands and `vp <command> --help` for information about a specific command.

Docs are local at `node_modules/vite-plus/docs` or online at https://viteplus.dev/guide/.

## Built-in Commands vs Scripts

`vp <name>` runs a built-in command. `vp run <name>` runs a `package.json` script or a `vite.config.ts` task. Scripts cannot overwrite built-ins, so `vp dev` and `vp run dev` may do different things. Check `package.json` and `vite.config.ts` first, and run `vp run <name>` when the project defines a script or task with that name.

## Running Scripts

Run TypeScript and JavaScript files with `vpx <file>`, for example `vpx ./scripts/seed.ts --dry-run`. It handles enums, decorators, JSX, and tsconfig `paths`, so do not add `tsx` or `ts-node` to run scripts. `vpx --watch <file>` reruns the file when a file it uses changes, in place of `tsx watch`. `vp node <file>` runs plain Node.js.

## Tool Versions

Run `vp toolchain` to show versions and relationships in the active Vite+
release. Add a tool name to select part of the graph. For example, run
`vp toolchain vite`. Use `--global` to ignore the local `vite-plus` package. Use
`vp why <package>` to show the package-manager dependency graph.

## Review Checklist

- [ ] Run `vp install` after pulling remote changes and before getting started.
- [ ] Run `vp check` and `vp test` to format, lint, type check and test changes.
- [ ] Check if there are `vite.config.ts` tasks or `package.json` scripts necessary for validation, run via `vp run <script>`.
- [ ] If setup, runtime, or package-manager behavior looks wrong, run `vp env doctor` and include its output when asking for help.

<!--VITE PLUS END-->

# clankerauth

Layout and house rules; the README says what the product does. `vp run ready` checks everything.

## Server (`apps/server/src`)

Grouped by domain. `tests/` mirrors it, with suites over the whole application at its root.

- `owner/`: the account: setup, sessions, owner authentication, temporary provider sessions.
- `clients/`: OAuth clients; `managed.ts` tells a managed client from a self-registered one.
- `resources/`: the catalog (`catalog.ts`, which knows the built-in resource), its writes and
  client access (`resources.ts`).
- `authorization/`: consents, codes and tokens, keyed by resource reference.
- `api-keys/`: API keys and the signed key lists resource servers verify them with.
- `forward-auth/`: forward-auth routes for a reverse proxy.
- `issuer/`: settings, the Better Auth instance (`Issuer`), provider errors and cookies.
- `platform/`: SQLite, the Node listener and request policy, the CIMD transport.
- `http/`: the HTTP and MCP surface over every domain.

Technology enters only through `platform/`, `issuer/` and, to serve HTTP, `http/`. Each service is a `Context.Service`
with a static `layer` that captures its dependencies; a method requires only request context,
such as `CurrentOwner`. `services.ts` builds the graph, and Layers are chosen in `main.ts`,
`tests/test-issuer.ts` and `packages/dev`. `embed.ts` (`@clankerauth/server/embed`) is the only
server source importable from outside `apps/server`.

`CurrentOwner.providerHeaders` is the provider session administration acts through, so the
dashboard reuses its request's cookie instead of opening a session per call. It is `Redacted`:
unwrap it only to hand it to the provider.

## Web (`apps/web/src`)

Foldkit's layout: the root files at `src/`, pages in `page/`, the dashboard in `page/dashboard/`.
`api.ts` is the issuer client.

## Packages

- `packages/admin-api` (published): the administration contract: actions, schemas and errors.
- `packages/sdk` (published): one module per entry; owns the protocol constants resource
  servers share with the issuer.
- `packages/dev` (published): the development issuer, built on the embed entry.
- `apps/cli` (published): the CLI; the SDK's `/credentials` owns signing in, the sign-in file
  and its refresh.

## Rules

- Every administration operation is an action in `packages/admin-api`; HTTP, MCP, the CLI and
  the dashboard derive from it.
- A contract error names its subject and carries its `message`; an action declares only the
  failures it can produce. A provider call names what each status means to it
  (`provider(call, { refused, missing, … })`); any other failure is `InternalServerError`.
- Server and SDK tests return Effects (`@effect/vitest`), `it.live` when wall-clock time is
  read. Effect is run by hand only in a callback foreign code calls. Suites that drive a real
  process, and the web app's Foldkit tests, are exempt.
- `tools/oxlint/clankerauth` enforces each folder's import allow-list and where Effect may be
  run by hand. The root `oxlint.config.ts` holds the lists and
  `tools/oxlint/clankerauth/tests/policy.test.ts` proves them; the rules read syntax only.

## Lint and format

`vp check` formats, lints and type-checks; `vp check --fix` applies the safe fixes. Lint comes
from `@clanker-stuff/oxlint-config` through `config()` in `oxlint.config.ts`, with this
repository's overrides there: Foldkit's recommended preset for `apps/web/src` and the
`clankerauth` plugin. Warnings fail the check. `vp install` patches the linter for the Effect
rules (the `prepare` script); after installing with `--ignore-scripts`, run `vp run prepare`.
Fix the code rather than add a lint exception. `vp config` rewrites the Vite+ block of this
file on every install, so the formatter skips `AGENTS.md`.

## Constraints from dependencies

What Better Auth, its plugins and the platform force on the code:

- Provider calls cannot be cancelled. HTTP routes run them uninterruptibly, and migration and
  initialization finish before the database closes.
- Provider APIs own their transactions: never hold one around them on the shared connection.
  The sign-up hook runs inside the provider's transaction, so it reads through that adapter,
  and the provider refuses an existing email before the hook can answer a conflict.
- Authorization codes live in the `verification` table, outside the client's foreign keys, so
  deleting a client cascades nothing to them. There is no bulk revocation API.
- `consentReferenceId` enforces resource access; the provider's per-client check is off
  because it needs every client linked to its resources. The provider validates the resource
  on token requests itself. Its client scopes are rebuilt with SQL, without a session.
- Dynamic registration defaults to web clients, which refuse the loopback redirects MCP
  clients register, so a loopback registration becomes `native`; its `resources` are dropped
  because consent picks them.
- The plain create-client endpoint drops `skip_consent`; the administrative one keeps it. The
  update endpoint cannot change `token_endpoint_auth_method`. A public client's secret fields
  come back `undefined`.
- The JWT plugin mints a missing signing key on first use, and two first uses mint two, so the
  issuer reads the JWKS once at startup. The API-key plugin's rate limit guards only its verify
  endpoint, which offline verification never calls, so it is off.
- Core errors carry `message`; the OAuth provider sends `error_description`.
- The `dontRememberToken` cookie keeps `getSession` from extending a request-local session.
- The provider's browser client follows OAuth redirects itself. It refuses an empty scope, and
  an omitted scope approves everything requested.
- The secure CIMD transport cannot abort its DNS lookup, so its capacity stays held until the
  lookup settles. Kysely owns connection cleanup once its dialect is initialized.
- Stateless MCP (2026-07-28) is POST only, with no session or resumption headers.
- Credentials refresh uninterruptibly: the issuer rotates the refresh token as it answers.
- Node's `fetch` sets `Sec-Fetch-Mode`, the header that tells the issuer whether a request may
  be redirected through sign-in, so the dev edge relays with `node:http`. Vite's proxy claims
  `upgrade` before an async check ends, so the edge's listener goes first, and a socket reset
  is reported, never thrown, since it would crash the dev server.
- Vite+'s task cache does not track the TypeScript 7 compiler's reads, so the SDK and contract
  builds are uncached; in the dev package `vp pack` clears `dist`, so its build is uncached
  too. `pnpm pack` resolves `catalog:` in a manifest; `npm pack` does not.

## Dependencies and environments

- Dependabot updates only the SHA-pinned GitHub Actions; npm dependencies move by hand through
  the pnpm catalog.
- `.agents/setup` prepares an agent environment. Do not snapshot identity state, owner
  credentials or signing secrets into it.

## Effect

Before writing or reviewing Effect code, read `node_modules/effect/AGENTS.md` in the package you are changing and the examples it links under `ai-docs/`. They ship with the installed `effect`, so they match the APIs the code compiles against. For exact signatures, read that package's installed source and types in `node_modules/effect` and `node_modules/@effect/*`. Do not write Effect APIs from memory or from examples for another version.
