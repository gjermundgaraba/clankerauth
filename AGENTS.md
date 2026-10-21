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
