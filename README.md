# clankerauth

A small self-hosted OAuth authorization server for private-network apps and MCP servers. One owner account with local password login and first-run setup in the browser. S256 PKCE on every flow, audience-bound JWT access tokens, rotating refresh tokens, scoped API keys that resource servers verify offline, and automatic client onboarding through Client ID Metadata Documents (CIMD) and Dynamic Client Registration (DCR). No external identity provider, no open signup, no organizations.

Built on Node 26, [Better Auth](https://better-auth.com) with its OAuth provider, API key and CIMD plugins, [Effect](https://effect.website), Vite+ and SQLite through `node:sqlite`.

## Run it

Create an env file with `CLANKERAUTH_BASE_URL` and `CLANKERAUTH_BETTER_AUTH_SECRET`, then:

```sh
docker build -t clankerauth .
docker volume create clankerauth-data
docker run --name clankerauth --env-file clankerauth.env -v clankerauth-data:/data \
  -p 127.0.0.1:3000:3000 --restart unless-stopped clankerauth
```

Without Docker: `vp install --frozen-lockfile && vp run build && vp run start`, which reads `.env` from the working directory. See `.env.example`.

Open the configured origin, create the owner account, and add a resource. Do this on the private network before exposing the service.

| Variable                               | Meaning                                                                                                                                                                                                                                                                                                               |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CLANKERAUTH_BASE_URL`                 | Public origin without a path. HTTPS unless loopback or `CLANKERAUTH_ALLOW_INSECURE_HTTP`. The OAuth issuer is `CLANKERAUTH_BASE_URL/api/auth`.                                                                                                                                                                        |
| `CLANKERAUTH_BETTER_AUTH_SECRET`       | At least 32 random characters, for example `openssl rand -hex 32`. Encrypts signing keys and signs cookies; keep it with your backups.                                                                                                                                                                                |
| `CLANKERAUTH_DATABASE`                 | SQLite file, default `data/clankerauth.sqlite`. Persist the whole directory. The container defaults to `/data/clankerauth.sqlite`.                                                                                                                                                                                    |
| `CLANKERAUTH_MCP_ALLOWED_ORIGINS`      | Comma-separated additional browser origins allowed to call administration MCP. Exact HTTPS origins, or loopback HTTP for development; defaults to none.                                                                                                                                                               |
| `CLANKERAUTH_HOST`, `CLANKERAUTH_PORT` | Bind address and port, default `127.0.0.1:3000`. The container defaults to `0.0.0.0:3000`.                                                                                                                                                                                                                            |
| `CLANKERAUTH_TRUST_PROXY`              | `true` when a reverse proxy sets `X-Forwarded-For`; the last hop becomes the client address for rate limiting. Default `false`.                                                                                                                                                                                       |
| `CLANKERAUTH_ALLOW_INSECURE_HTTP`      | `true` permits a plain-HTTP issuer and MCP origins beyond loopback, for private networks without TLS. Default `false`.                                                                                                                                                                                                |
| `CLANKERAUTH_COOKIE_DOMAIN`            | Parent domain of `CLANKERAUTH_BASE_URL`, for example `home.example`, that the forward-auth cookie is shared with. Required for forward auth; without it the routes are not served.                                                                                                                                    |
| `OTEL_*`                               | Standard [OpenTelemetry environment variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/): set `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces, metrics and logs to a collector; headers, timeouts and `OTEL_SDK_DISABLED` are honoured. Unset means no telemetry is exported. |

Run it behind a reverse proxy with TLS. The server uses `CLANKERAUTH_BASE_URL` as its canonical origin and ignores forwarded host and protocol headers, except on `/forward-auth`, where they only decide where a browser returns after login. Rate limits key on the direct peer address unless `CLANKERAUTH_TRUST_PROXY=true`, in which case the last `X-Forwarded-For` hop set by your proxy is used. Run one instance per database; SQLite runs in WAL mode on a local filesystem. `/healthz` reports database connectivity. Back up by stopping the server and copying the database directory, or use SQLite's backup API while running. There is no password recovery: keep the owner password in a password manager, and keep the database and secret together.

Shutdown disconnects HTTP clients, including active streams, without waiting for response delivery. Already-running provider operations must settle before SQLite closes; an uncancellable operation that never settles can still delay shutdown.

## Connect a client

Add a **Resource** in the dashboard. Its identifier is the exact URL that clients send as the `resource` parameter and that becomes the token audience; its scopes are the permissions it defines. Then:

- **MCP clients** onboard themselves. Point the client at your MCP server; it discovers this issuer from the server's protected-resource metadata, registers through CIMD or DCR, and asks the owner for consent once per resource. Such an automatic client may ask for any resource, including ones added later; consent is the gate. The owner can untick requested scopes on the consent screen to grant less than was asked.
- **Your own applications** are registered by the owner under **Register client** with one or more exact redirect URIs. They are first party: a signed-in owner is sent straight back with a code, with no consent screen, so the owner chooses which resources each may obtain. Confidential clients authenticate with HTTP Basic or a secret in the request body and receive a one-time secret. Name, redirect URIs and application type can be edited later.

Every authorization request names exactly one `resource`; token requests may omit it and reuse the resource bound to the code or refresh token. The owner's login session lasts 30 days and slides with use, so signing in for one application signs in for all of them. Access tokens are EdDSA JWTs valid for fifteen minutes; refresh tokens last 30 days and rotate on every use, with a thirty-second reuse window so a retried refresh does not revoke the family. The dashboard shows each client's connections, the authorization it holds: every resource it has a consent or a live refresh token for, with its scopes, the approval time and when it last received a refresh token. A managed client skips consent, so it shows a connection while it holds a refresh token. **Revoke** ends one connection and **Revoke all** ends every one; the client must authorize again, and an automatic one asks for consent. Removing a resource from a managed client's access, or deleting the resource, also revokes that authorization, so restoring access never revives it. **Block client** revokes everything and stops the client from authorizing again. **Delete client** forgets any client; an automatic one can register again, so block it to keep it out. None of these recalls an already-issued access token; it expires within fifteen minutes.

Discovery is served at `/.well-known/oauth-authorization-server/api/auth`. There is no OpenID Connect: no ID tokens, no UserInfo, and `openid` is not a supported scope.

## Protect a web app behind a reverse proxy

Browser applications need no OAuth code of their own. Put them behind Caddy or Traefik with forward auth pointed at this issuer, and add the app's API as a **Resource**. On every browser request the proxy asks `/forward-auth`; a signed-in owner gets a fifteen-minute access token for that resource in an `Authorization` header, which the proxy copies upstream. Anyone else is sent through the issuer, which signs them in if needed, and back to the page they asked for; only page navigations (`Sec-Fetch-Mode: navigate`) are redirected, and any other request, such as a script's `fetch`, is answered `401` so the app can reload instead of chasing a cross-origin redirect. The app verifies the token exactly as it verifies MCP and API-key bearer tokens below. Requests that already carry an `Authorization` header (MCP clients, API keys) bypass forward auth, and an MCP endpoint and the discovery documents under `/.well-known` stay public so MCP clients receive the 401 challenge they onboard from; one origin then serves browsers and agents alike.

Register **one** resource per application, identified by its public origin root with the trailing slash: `https://notes.home.example/`. That one resource covers `/api`, `/mcp` and any socket, so the app publishes one RFC 9728 document at `/.well-known/oauth-protected-resource`, verifies one audience, and the proxy needs one `forward_auth` block. An identifier must already be canonical (`new URL(id).href === id`): a client sends back exactly what discovery published, and the dashboard refuses a form the client would rewrite, such as `https://notes.home.example` without its slash.

```caddyfile
notes.home.example {
  @browser {
    not header Authorization *
    not path /mcp /mcp/* /.well-known/* /healthz
  }
  forward_auth @browser https://clankerauth.home.example {
    uri /forward-auth?resource=https://notes.home.example/
    copy_headers Authorization
  }
  reverse_proxy notes:8080
}
```

Set `CLANKERAUTH_COOKIE_DOMAIN` to the domain the issuer and the apps share, here `home.example`; forward auth is served only when it is set. The owner's issuer session cookie never leaves the issuer host. After login the browser passes through `/forward-auth/continue`, which sets a separate forward cookie on that domain: the session sealed under the server secret, meaningful only to `/forward-auth`. Apps behind the proxy therefore see the forward cookie and the access token, and neither can administer the issuer; an app could at most use the cookie to obtain tokens for other resources under the same domain, which in a single-owner network are the owner's own. Sign-out at the issuer or at `https://clankerauth.home.example/forward-auth/logout?rd=<page>` invalidates every copy of the cookie; it is a plain link, so any page under the domain can sign the owner out, which a single-owner network accepts. Logout always ends the session first, so an `rd` outside the cookie domain is answered with a redirect to `/login` rather than an error; only `/forward-auth/continue` refuses an unusable `rd` with 400, because it has nowhere to send the browser afterwards. The token's `client_id` is `forward-auth` and it carries all of the resource's scopes. The built-in administration resource is refused. The app verifies a signed token for its own resource rather than trusting proxy headers, so reaching it directly yields only `401`s.

## Protect a resource server

Verify access tokens with Better Auth's helper, pinning issuer and audience:

```ts
import { requestToResourceInput, verifyAccessTokenRequest } from "better-auth/oauth2";

const claims = await verifyAccessTokenRequest(requestToResourceInput(request), {
  jwksUrl: "https://clankerauth.internal/api/auth/jwks",
  verifyOptions: {
    issuer: "https://clankerauth.internal/api/auth",
    audience: "https://notes.internal/",
    algorithms: ["EdDSA"],
    typ: "at+jwt",
  },
  requiredScopes: ["notes:read"],
});
```

MCP servers additionally publish RFC 9728 protected-resource metadata that lists this issuer under `authorization_servers`, and answer unauthenticated requests with a `WWW-Authenticate: Bearer resource_metadata="…"` challenge.

For CLIs and automation, the owner creates **API keys** with explicit per-resource scopes. A resource server verifies them offline, against its **key list**:

```http
POST /api/keyList
Content-Type: application/json

{ "resource": "https://notes.internal/" }
```

`200` returns `{ list }`: a JWT with header `typ: key-list+jwt`, signed with the same EdDSA key as access tokens and published in the same JWKS, whose `aud` is the resource and whose `keys` claim holds one entry per enabled, unexpired key granted on it. An entry is found by, and sealed under, values derived from the key's SHA-256 digest and the resource identifier, so only a holder of the key can find or read it: its key ID, owner ID, the scopes it still has on that resource, and its expiry. Anyone else still sees how many entries the resource has, when they come and go, and roughly how large each grant is. An unknown resource, and administration, which keys never reach, get a list with no entries. The request needs no credential, so a resource server is configured with nothing but the issuer URL and its own resource identifier.

A list is valid for 24 hours from `iat`, and the SDK reads the next one after a minute. A key's expiry is checked on every request. A key disabled, deleted or re-scoped keeps the access it had until that next read, within about a minute. A key created, enabled or granted on the resource works within seconds: a key the held list does not name has the list read again first, at most once every five seconds. A resource server that cannot reach the issuer keeps deciding from the last list it read, until that list expires. That day is also the longest a revoked key stays usable during an outage. Lists are re-signed on every read, so rotating the signing key needs nothing but publishing the new key. A key is a bearer secret: any resource it is granted on can replay it to the others, so give a resource you trust less its own key. Every timestamp this issuer reads or writes is an ISO-8601 instant in UTC; a value without an offset is read as UTC, never as the host's local time. The dashboard lists the first 100 keys.

[`@gjermundgaraba/clankerauth-sdk`](packages/sdk/README.md) provides Effect-native access-token and offline API-key verification, a host/origin request policy for apps behind forward auth, and one admission function a socket can use outside an Effect router. Its optional `/effect-actions` integration declares an application's resource from its scopes and supplies the provider that authenticates every protected route and tool call and publishes discovery. Which scope an action needs stays the application's rule, written as its authorizer with the resource's `requires(scope)`, such as `action.readOnly ? Effect.void : Notes.requires("notes:write")`. Two entry points, `/errors` and `/session`, are browser-safe: a page imports `ProviderUnavailable`, the error a descriptor declares, the `whoami` contract and the sign-out URL without pulling verification into its bundle. Its API is Effect-only, and its `/testing` entry is a signing fake issuer for tests that only need JWKS and key lists. To develop or test against a real issuer locally, [`@gjermundgaraba/clankerauth-dev`](packages/dev/README.md) starts one with your resources and a client already provisioned, optionally persistent, and ships the development forward-auth edge so no application writes one again.

## Develop

```sh
vp install --frozen-lockfile
vp -C apps/web exec playwright install chromium
vp run dev      # dashboard on :3000, API on :3001, state in .dev/
vp run ready    # format, lint, types, builds, all tests
vp run test:lint # lint-policy regression fixtures
```

- `packages/admin-api`: the issuer administration contract defined with effect-actions, shared by server and dashboard.
- `apps/server`: the service. `vp pack` emits a single `dist/main.mjs`.
- `apps/web`: the dashboard, plain TypeScript built by Vite.
- `packages/sdk`: the `@gjermundgaraba/clankerauth-sdk` npm package for services that authenticate against an issuer. Its tests run against the in-repo server.
- `packages/dev`: the `@gjermundgaraba/clankerauth-dev` npm package. Its tests also install the packed tarball and run against it.
- `apps/cli`: the `@gjermundgaraba/clankerauth` npm package, the `clankerauth` command. Its tests run the packed binary against a development issuer.

The three packages are public on npm. A `v*` tag matching their shared version publishes them from `.github/workflows/npm.yml` through npm trusted publishing: each package names this repository and that workflow file as its trusted publisher, so no registry token is stored. npm can only register a trusted publisher on a package that already exists, so the first release of a new package name is published by hand with `pnpm publish` from its directory after `npm login`.

### effect-actions integration

Custom API operations use
[`@gjermundgaraba/effect-actions`](https://github.com/gjermundgaraba/effect-actions)
and are exposed at `POST /api/<action>`. No-input actions take
`{}`; create actions return HTTP 201. OAuth protocol endpoints and the
operational `GET /healthz` endpoint are separate.

| Action                 | Access                                                                          | Transport |
| ---------------------- | ------------------------------------------------------------------------------- | --------- |
| `setupStatus`          | Public                                                                          | HTTP      |
| `setupOwner`           | Public; succeeds only before an owner exists                                    | HTTP      |
| `keyList`              | Public; entries are sealed to the keys they describe                            | HTTP      |
| Administration actions | Owner session cookie (SameSite), at `POST /api/<action>`                        | HTTP      |
| Administration actions | OAuth access token for `<CLANKERAUTH_BASE_URL>/`, at `POST /api/owner/<action>` | HTTP      |
| Administration tools   | OAuth access token for `<CLANKERAUTH_BASE_URL>/`, at `/mcp`                     | MCP       |

A token needs `clankerauth:read` to list and `clankerauth:write` for everything else, over
HTTP and MCP alike. Issuer actions and the dashboard's owner operations share one binding,
`POST /api/<action>`; `/api/owner/<action>` serves the same owner operations to an access
token, as the `clankerauth` command calls them, and nothing else. The
dashboard uses the direct typed action client. Input that does not decode, or that
decodes but the issuer's own checks refuse, answers effect-actions' built-in
`InvalidInput` (400), naming the field at fault. Input the provider rejects, such as a
short password, an invalid email or a redirect URI, a request body the issuer cannot
read, and a request its state refuses answer `BadRequest` (400) with an `error` message
and no field. Data the issuer cannot read answers sanitized `InternalServerError` JSON
(500). MCP uses native tool errors: declared domain
failures are JSON text with `isError: true`, while schema failures use native
validation/internal-error messages. Successful tool results return the action's output
as `structuredContent`.

### Connect to administration MCP

Point an OAuth-capable MCP client at `<CLANKERAUTH_BASE_URL>/mcp`. The client discovers
this issuer, registers using CIMD or DCR, and opens the owner login and consent
page. `clankerauth:read` allows the listing tools: clients, resources, connections and
API-key metadata. `clankerauth:write` allows every tool, including client and API-key
creation, and so amounts to access to every resource. Untick `clankerauth:write` on the consent screen to give an agent read-only access. Create and rotate operations return secrets once.
No separate dashboard grant is needed.

For browser-hosted MCP clients, add their origins to the server environment:

```sh
CLANKERAUTH_MCP_ALLOWED_ORIGINS=https://mcp.example.com,http://localhost:5173
```

These are exact web origins, without paths, trailing slashes, or wildcards. The
issuer's own origin is always allowed. The same allowlist governs MCP Origin
validation and CORS, including preflight and exposed authentication/session headers.
Actual MCP requests require OAuth bearer tokens; browser clients should omit
cookies. Native and server clients that send no Origin need no allowlist entry.
This setting does not grant OAuth access or relax the dashboard's cookie policy.

The built-in **clankerauth administration** resource is created at startup, identified by
the issuer's origin root with its trailing slash, `<CLANKERAUTH_BASE_URL>/`, as an
application's resource is. Its tokens are taken at `/mcp` and `/api/owner/<action>`; the
dashboard at `/` takes the owner's session cookie alone. Before 0.16.0 it was
`<CLANKERAUTH_BASE_URL>/mcp`.
It is fixed: every start restores its name and scopes, and it cannot be edited or deleted. Protected-resource metadata
is public at `/.well-known/oauth-protected-resource` and advertises `clankerauth:read`,
`clankerauth:write` and `offline_access`. Clients must send the resource parameter during authorization
and token exchange. The authentication challenge requests both administration scopes, so
the owner decides at consent. Clients
that want rotating refresh tokens also request `offline_access` and declare the
`refresh_token` grant type. Access tokens last fifteen minutes; clients without refresh
access must authorize again after expiration.

Every MCP and `/api/owner` request requires a bearer OAuth access token, verified with the same SDK as consumer resource servers. Owner cookies and API keys do not authenticate MCP, and API keys cannot be granted administration permissions. Tokens must belong to this issuer, owner and resource with `clankerauth:read` or `clankerauth:write`, and their client must still exist and not be blocked; a token with neither gets `insufficient_scope`. Every tool is listed, and a call to a changing tool without `clankerauth:write` is refused with an HTTP 403 `insufficient_scope` challenge naming that scope, on which an OAuth client steps up. **Block client** and deletion therefore end MCP access on the next request; **Revoke** ends refresh, and the current access token expires within fifteen minutes. Unblocking does not restore revoked grants. Browser-session expiry and dashboard sign-out do not revoke administration MCP access.

MCP serves only the stateless **2026-07-28** revision; clients of the earlier,
session-based revisions are refused. OAuth clients must support resource indicators. Effect's native
HTTP server streams responses instead of buffering them; historical two-endpoint
SSE remains unsupported. Request bodies are limited to 64 KiB; larger uploads are disconnected.

`GET /openapi.json` is public.

```sh
curl "$CLANKERAUTH_BASE_URL/api/listClients" \
  -H "Cookie: $OWNER_COOKIE" \
  -H 'Content-Type: application/json' -d '{}'
```

### Administer from the command line

`@gjermundgaraba/clankerauth` is the `clankerauth` command, every administration action
over `/api/owner`:

```sh
npm install --global @gjermundgaraba/clankerauth
clankerauth login https://clankerauth.home.example   # approve in the browser
clankerauth list-clients
clankerauth create-api-key --name "notes sync" \
  --permissions '{"https://notes.home.example/":["notes:read"]}' --expires-at null
clankerauth logout
```

`login` registers the command as a native client the first time, prints the approval URL
on stderr and opens it, unless `--no-browser`, and listens for the redirect on a loopback
port. `--read-only` asks for `clankerauth:read` alone. The sign-in is kept in
`$XDG_CONFIG_HOME/clankerauth/credentials.json`, by default under `~/.config`, readable by
its owner alone; a command refreshes the access token when it has expired and saves the
rotated refresh token, so a sign-in lasts while it is used at least every 30 days.
`logout` revokes it and deletes the file.

Each action is a command named after it in kebab case, with a flag per input field, as
`clankerauth <command> --help` shows. A command prints the action's result as JSON on
stdout and a refusal on stderr, exiting 1. A created API key or client secret is in that
JSON once, so redirect it where it belongs rather than to a terminal:
`clankerauth create-api-key … | jq -r .key > key`.

See the breaking [0.16.0](docs/releases/0.16.0.md), [0.13.0](docs/releases/0.13.0.md), [0.11.0](docs/releases/0.11.0.md), [0.10.0](docs/releases/0.10.0.md), [0.9.0](docs/releases/0.9.0.md), [0.8.0](docs/releases/0.8.0.md) and [0.7.0](docs/releases/0.7.0.md) release notes before upgrading an issuer or SDK.

[docs/domain-language.md](docs/domain-language.md) defines the vocabulary used in the UI and code.

## License

[MIT](LICENSE)
