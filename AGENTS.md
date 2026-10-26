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
dashboard reuses its request's cookie instead of opening a session per call.

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
- No prose comments. Allowed: tool directives with a reason, one-line `// SAFETY:` and
  `// why:`, `/** */` on types and schemas, the published packages' API docs, and Foldkit's
  section headers.
- `tools/oxlint/clankerauth` enforces the comment rule, each folder's import allow-list and
  where Effect may be run by hand. The root `vite.config.ts` holds the lists and
  `tests/policy.test.mjs` proves them; the rules read syntax only.

## Effect

Before writing or reviewing Effect code, read `node_modules/effect/AGENTS.md` in the package you are changing and the examples it links under `ai-docs/`. They ship with the installed `effect`, so they match the APIs the code compiles against. For exact signatures, read that package's installed source and types in `node_modules/effect` and `node_modules/@effect/*`. Do not write Effect APIs from memory or from examples for another version.
