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

Without Docker: `pnpm install --frozen-lockfile && pnpm build && pnpm start`, which reads `.env` from the working directory. See `.env.example`.

Open the configured origin, create the owner account, sign in, and add a resource. Do this on the private network before exposing the service.

| Variable             | Meaning                                                                                                                                |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_BASE_URL`      | Public origin without a path. HTTPS unless loopback. The OAuth issuer is `AUTH_BASE_URL/api/auth`.                                     |
| `BETTER_AUTH_SECRET` | At least 32 random characters, for example `openssl rand -hex 32`. Encrypts signing keys and signs cookies; keep it with your backups. |
| `AUTH_DATABASE`      | SQLite file, default `data/auth.sqlite`. Persist the whole directory. The container defaults to `/data/auth.sqlite`.                   |
| `HOST`, `PORT`       | Bind address and port, default `127.0.0.1:3000`. The container defaults to `0.0.0.0:3000`.                                             |

Run it behind a reverse proxy with TLS. The server trusts only `AUTH_BASE_URL`, never forwarding headers, and rate-limits by direct peer address, so enforce per-client limits at the proxy. Run one instance per database; SQLite runs in WAL mode on a local filesystem. `/healthz` reports database connectivity. Back up by stopping the server and copying the database directory, or use SQLite's backup API while running. There is no password recovery: keep the owner password in a password manager, and keep the database and secret together.

## Connect a client

Add a **Resource** in the dashboard. Its identifier is the exact URL that clients send as the `resource` parameter and that becomes the token audience; its scopes are the permissions it defines. Then:

- **MCP clients** onboard themselves. Point the client at your MCP server; it discovers this issuer from the server's protected-resource metadata, registers through CIMD or DCR, and asks the owner for consent.
- **Other clients** are registered by the owner under **Register client** with an exact redirect URI. Confidential clients receive a one-time secret.

Every authorization and token request names exactly one `resource` and needs owner consent per resource. Access tokens are EdDSA JWTs valid for five minutes; refresh tokens last 30 days and rotate on every use. The dashboard lists every client: **Revoke authorization** clears its stored grants, **Block client** also stops it from authorizing again.

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
POST /api/api-keys/verify
Authorization: Bearer ca_…
Content-Type: application/json

{ "resource": "https://notes.internal/mcp" }
```

`200` returns `{ keyId, ownerId, resource, scopes, expiresAt }`. `401` means the key is invalid, disabled or expired; `403` that it has no scopes on that resource; `429` that it exceeded 1,000 verifications in a minute. Verify on every request so that disabling a key takes effect on the next one.

To test a client or resource server locally, [`@gjermundgaraba/clankerauth-dev`](packages/dev/README.md) starts a throwaway issuer with your resources and a client already provisioned.

## Develop

```sh
pnpm install --frozen-lockfile
pnpm --filter @clankerauth/web exec playwright install chromium
pnpm dev      # dashboard on :3000, API on :3001, state in .dev/
pnpm ready    # format, lint, types, builds, all tests
```

- `packages/api`: the Effect `HttpApi` contract shared by server and dashboard.
- `apps/server`: the service. `vp pack` emits a single `dist/main.mjs`.
- `apps/web`: the dashboard, plain TypeScript built by Vite.
- `packages/dev`: the `@gjermundgaraba/clankerauth-dev` npm package. Its tests also install the packed tarball and run against it; a `v*` tag publishes it.
- `patches/`: two pinned fixes to the Better Auth plugins, explained in [docs/provider-integration.md](docs/provider-integration.md).

[docs/domain-language.md](docs/domain-language.md) defines the vocabulary used in the UI and code.

## License

[MIT](LICENSE)
