# Clanker Auth

A small self-hosted OAuth authorization server for private-network apps and MCP servers. One owner account with local password login and first-run setup in the browser. S256 PKCE on every flow, audience-bound JWT access tokens, rotating refresh tokens, scoped API keys, and automatic client onboarding through Client ID Metadata Documents (CIMD) and Dynamic Client Registration (DCR). No external identity provider, no open signup, no organizations.

Built on Node 26, [Better Auth](https://better-auth.com) with its OAuth provider, API key and CIMD plugins, [Effect](https://effect.website), Vite+ and SQLite through `node:sqlite`.

## Run it

Create an env file with `AUTH_BASE_URL` and `BETTER_AUTH_SECRET`, then:

```sh
docker build -t clankerauth .
docker volume create clankerauth-data
docker run --name clankerauth --env-file clankerauth.env -v clankerauth-data:/data \
  -p 127.0.0.1:3000:3000 --restart unless-stopped clankerauth
```

Without Docker: `vp install --frozen-lockfile && vp run build && vp run start`, which reads `.env` from the working directory. See `.env.example`.

Open the configured origin, create the owner account, and add a resource. Do this on the private network before exposing the service.

| Variable              | Meaning                                                                                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_BASE_URL`       | Public origin without a path. HTTPS unless loopback or `ALLOW_INSECURE_HTTP`. The OAuth issuer is `AUTH_BASE_URL/api/auth`.                             |
| `BETTER_AUTH_SECRET`  | At least 32 random characters, for example `openssl rand -hex 32`. Encrypts signing keys and signs cookies; keep it with your backups.                  |
| `AUTH_DATABASE`       | SQLite file, default `data/auth.sqlite`. Persist the whole directory. The container defaults to `/data/auth.sqlite`.                                    |
| `MCP_ALLOWED_ORIGINS` | Comma-separated additional browser origins allowed to call administration MCP. Exact HTTPS origins, or loopback HTTP for development; defaults to none. |
| `HOST`, `PORT`        | Bind address and port, default `127.0.0.1:3000`. The container defaults to `0.0.0.0:3000`.                                                              |
| `TRUST_PROXY`         | `true` when a reverse proxy sets `X-Forwarded-For`; the last hop becomes the client address for rate limiting. Default `false`.                         |
| `ALLOW_INSECURE_HTTP` | `true` permits a plain-HTTP issuer and MCP origins beyond loopback, for private networks without TLS. Default `false`.                                  |

Run it behind a reverse proxy with TLS. The server uses `AUTH_BASE_URL` as its canonical origin and ignores forwarded host and protocol headers. Rate limits key on the direct peer address unless `TRUST_PROXY=true`, in which case the last `X-Forwarded-For` hop set by your proxy is used. Run one instance per database; SQLite runs in WAL mode on a local filesystem. `/healthz` reports database connectivity. Back up by stopping the server and copying the database directory, or use SQLite's backup API while running. There is no password recovery: keep the owner password in a password manager, and keep the database and secret together.

Shutdown disconnects HTTP clients, including active streams, without waiting for response delivery. Already-running provider operations must settle before SQLite closes; an uncancellable operation that never settles can still delay shutdown.

## Connect a client

Add a **Resource** in the dashboard. Its identifier is the exact URL that clients send as the `resource` parameter and that becomes the token audience; its scopes are the permissions it defines. Then:

- **MCP clients** onboard themselves. Point the client at your MCP server; it discovers this issuer from the server's protected-resource metadata, registers through CIMD or DCR, and asks the owner for consent once per resource.
- **Your own applications** are registered by the owner under **Register client** with one or more exact redirect URIs. They are first party: a signed-in owner is sent straight back with a code, with no consent screen. Confidential clients authenticate with HTTP Basic or a secret in the request body and receive a one-time secret. Name, redirect URIs and application type can be edited later.

Every authorization request names exactly one `resource`; token requests may omit it and reuse the resource bound to the code or refresh token. The owner's login session lasts 30 days and slides with use, so signing in for one application signs in for all of them. Access tokens are EdDSA JWTs valid for fifteen minutes; refresh tokens last 30 days and rotate on every use, with a thirty-second reuse window so a retried refresh does not revoke the family. The dashboard lists every client: **Revoke authorization** clears its stored grants, **Block client** also stops it from authorizing again. Neither recalls an already-issued access token; it expires within fifteen minutes.

Discovery is served at `/.well-known/oauth-authorization-server/api/auth` and `/api/auth/.well-known/openid-configuration`.

## Protect a resource server

Verify access tokens with Better Auth's helper, pinning issuer and audience:

```ts
import { requestToResourceInput, verifyAccessTokenRequest } from "better-auth/oauth2";

const claims = await verifyAccessTokenRequest(requestToResourceInput(request), {
  jwksUrl: "https://auth.internal/api/auth/jwks",
  verifyOptions: {
    issuer: "https://auth.internal/api/auth",
    audience: "https://notes.internal/mcp",
    algorithms: ["EdDSA"],
    typ: "at+jwt",
  },
  requiredScopes: ["notes:read"],
});
```

MCP servers additionally publish RFC 9728 protected-resource metadata that lists this issuer under `authorization_servers`, and answer unauthenticated requests with a `WWW-Authenticate: Bearer resource_metadata="…"` challenge.

For CLIs and automation, the owner creates **API keys** with explicit per-resource scopes. A resource server verifies one with:

```http
POST /api/issuer/verifyApiKey
Authorization: Bearer ca_…
Content-Type: application/json

{ "resource": "https://notes.internal/mcp" }
```

`200` returns `{ keyId, ownerId, resource, scopes, expiresAt }`. `401` means the key is invalid, disabled or expired; `403` that it has no scopes on that resource; `429` that it exceeded 1,000 verifications in a minute. Verify on every request so that disabling a key takes effect on the next one. The dashboard lists the first 100 keys.

[`@gjermundgaraba/clankerauth-sdk`](packages/sdk/README.md) provides Effect-native access-token and API-key verification and browser login with server-held tokens. Its optional `/effect-actions` integration supplies authentication/discovery middleware. Its API is Effect-only; see its README for the breaking replacement of the Promise SDK. To test against a real issuer locally, [`@gjermundgaraba/clankerauth-dev`](packages/dev/README.md) starts a throwaway one with your resources and a client already provisioned.

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
- `packages/dev`: the `@gjermundgaraba/clankerauth-dev` npm package. Its tests also install the packed tarball and run against it. A `v*` tag publishes both packages at that version.

### effect-actions integration

Custom API operations use
[`@gjermundgaraba/effect-actions`](https://github.com/gjermundgaraba/effect-actions)
and are exposed at `POST /api/<groupName>/<actionName>`. No-input actions take
`{}`; create actions return HTTP 201. OAuth protocol endpoints and the
operational `GET /healthz` endpoint are separate.

| Action                 | Access                                                      | Transport |
| ---------------------- | ----------------------------------------------------------- | --------- |
| `setupStatus`          | Public                                                      | HTTP      |
| `setupOwner`           | Public; succeeds only before an owner exists                | HTTP      |
| `verifyApiKey`         | Bearer API key scoped to the requested resource             | HTTP      |
| Administration actions | Owner session cookie (SameSite)                             | HTTP      |
| Administration tools   | OAuth access token for `<AUTH_BASE_URL>/mcp`, scope `admin` | MCP       |

Issuer actions use the `issuer` group; owner operations use `administration`. The
dashboard uses the direct typed action client. HTTP schema-error handling returns
sanitized `BadRequest` JSON (400) for malformed input and `InternalServerError`
JSON (500) for invalid handler output. MCP uses native tool errors: declared domain
failures are JSON text with `isError: true`, while schema failures use native
validation/internal-error messages. Successful tool results use `structuredContent.value`.

### Connect to administration MCP

Point an OAuth-capable MCP client at `<AUTH_BASE_URL>/mcp`. The client discovers
this issuer, registers using CIMD or DCR, and opens the owner login and consent
page. Approving the `admin` scope grants full administration access, including
client and API-key creation. Create and rotate operations return secrets once.
No separate dashboard grant is needed.

For browser-hosted MCP clients, add their origins to the server environment:

```sh
MCP_ALLOWED_ORIGINS=https://mcp.example.com,http://localhost:5173
```

These are exact web origins, without paths, trailing slashes, or wildcards. The
issuer's own origin is always allowed. The same allowlist governs MCP Origin
validation and CORS, including preflight and exposed authentication/session headers.
Actual MCP requests require OAuth bearer tokens; browser clients should omit
cookies. Native and server clients that send no Origin need no allowlist entry.
This setting does not grant OAuth access or relax the dashboard's cookie policy.

The built-in **Clanker Auth administration** resource is created at startup.
Its display name can be changed; its identifier and scope are fixed, and the
resource cannot be deleted. Protected-resource metadata
is public at `/.well-known/oauth-protected-resource/mcp` and advertises `admin`
and `offline_access`. Clients must send the resource parameter during authorization
and token exchange. The authentication challenge requests only `admin`. Clients
that want rotating refresh tokens also request `offline_access` and declare the
`refresh_token` grant type. Access tokens last fifteen minutes; clients without refresh
access must authorize again after expiration.

Every MCP request requires a bearer OAuth access token, verified with the same SDK as consumer resource servers. Owner cookies and API keys do not authenticate MCP, and API keys cannot be granted administration permissions. Tokens must belong to this issuer, owner and resource with scope `admin`, and their client must still exist and not be blocked. **Block client** and deletion therefore end MCP access on the next request; **Revoke authorization** ends refresh, and the current access token expires within fifteen minutes. Unblocking does not restore revoked grants. Browser-session expiry and dashboard sign-out do not revoke administration MCP access.

MCP supports **2026-07-28**, **2025-11-25**, **2025-06-18**, and **2025-03-26**
transport revisions. OAuth clients must support resource indicators. Effect's native
HTTP server streams responses instead of buffering them; historical two-endpoint
SSE remains unsupported. Request bodies are limited to 64 KiB; larger uploads are disconnected.

`GET /openapi.json` is public.

```sh
curl "$AUTH_BASE_URL/api/administration/listClients" \
  -H "Cookie: $OWNER_COOKIE" \
  -H 'Content-Type: application/json' -d '{}'
```

See [the breaking 0.4.0 release notes](docs/releases/0.4.0.md) before upgrading an issuer or SDK.

[docs/domain-language.md](docs/domain-language.md) defines the vocabulary used in the UI and code.

## License

[MIT](LICENSE)
