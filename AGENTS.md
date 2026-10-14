# clankerauth

How the code is laid out, and the rules that keep it so. The README says what the product does.

## Server (`apps/server`)

Source is grouped by domain. Each domain folder holds its services, whose methods are the action
handlers; the wire schemas are `packages/admin-api`'s. Tests mirror the folders under `tests/`,
and suites over the composed application sit at the root of `tests/`.

- `owner/`: the sole account: setup, sessions, owner authentication for the dashboard, MCP and
  `/api/owner`, and the temporary provider sessions administration acts through.
- `clients/`: OAuth clients: listing, registration, editing, blocking, revocation and connections.
- `resources/`: the resource catalog (`catalog.ts`, reads) and its writes and client access
  (`resources.ts`).
- `authorization/`: stored authorization (consents, codes and tokens), keyed by resource reference.
- `api-keys/`: API keys and the signed key lists resource servers verify them against.
- `forward-auth/`: the reverse-proxy forward-auth routes.
- `issuer/`: settings, and the Better Auth instance the issuer is built on, with its plugins and
  the translation of its errors into the contract's.

Better Auth is the framework the issuer is built on, as Foldkit is the web app's: domains call its
API through the `Issuer` service. Other technology enters only through `platform/`: SQLite
(`sqlite.ts`), Node's HTTP server and request policy (`node-http.ts`), and the CIMD transport
(`cimd-transport.ts`).

Every domain service is a `Context.Service` with a declared interface, built by a Layer beside it
that captures its dependencies; a method requires only request-scoped context, such as
`CurrentOwner`. `services.ts` builds the whole graph from the `Settings` and `CimdTransport` Layers
it is given. `http/` is the HTTP and MCP surface over every domain. Layers are chosen in three
places: `main.ts` for the process, `tests/test-issuer.ts` for tests, and the development package.

The contract's `CurrentOwner` carries `providerHeaders`, the provider session administration
acts through: effect-actions' authentication provides one service per request, and the
dashboard's session reuses the request's own cookie rather than opening a session per call.

`embed.ts` is the server's one public entry, `@clankerauth/server/embed`, for the development
package. Nothing else imports server source from outside `apps/server`.

## Web (`apps/web`)

A Foldkit application, laid out as Foldkit's guidance says: the root files (`entry`, `main`,
`model`, `message`, `route`, `view`) at `src/`, and each page under `src/page/`, with the
dashboard's several files in `src/page/dashboard/`. `api.ts` is the issuer client. The paths the
issuer serves the document at are `src/document-paths.ts`, exported to the server.

## Packages

- `packages/admin-api`: the administration contract every surface is derived from: actions,
  schemas, errors, and the administration resource's identifier and scopes.
- `packages/sdk`: the published SDK, one folder-less module per entry. It owns the protocol
  constants resource servers share with the issuer, such as the API-key prefix and the sign-out
  path.
- `packages/dev`: the published development issuer, built from `@clankerauth/server/embed`.
- `apps/cli`: the published CLI; `oauth.ts` is its only OAuth adapter.

## House style

- **Operations as contracts**: every administration operation is an effect-actions action in
  `packages/admin-api`; HTTP, MCP, the CLI and the dashboard are derived from it.
- **Service and Layer together**: a service's Layer is a static member of its class.
- **Errors that carry context**: each contract error names its subject (`clientId`,
  `identifier`, `keyId`) and carries its sentence as a declared `message`, built once in the
  error's `of`; each action lists only the failures it can produce, which `Action.implement`
  checks. A provider call fails with `ProviderFailure`, keeping the provider's status, and its
  caller names what that status means (`refused`, `missing`, `internal` in `issuer/errors.ts`).
- **Effect-aware tests**: the server's and the SDK's tests are `@effect/vitest` tests that return
  Effects. Server tests take the issuer from the Layers in `tests/test-issuer.ts`, built fresh for
  each test; a test that reads wall-clock time, directly or through a library, is `it.live`.
  Effect is run by hand only inside a callback that non-Effect code calls (a mock, a Kysely
  transaction, a Node event, `expect.poll`), with the test's own services. Exempt: suites that
  drive a real process (`main.test.ts`, the CLI's, the development package's lifecycle) and the
  web app's, which use Foldkit's test harness.
