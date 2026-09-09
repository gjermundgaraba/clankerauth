# Clanker Auth

A single-instance, self-hosted identity and OAuth authorization server for private-network apps. Local password login, first-run web account creation, automatic and managed client registration, signed consent, S256 PKCE, and audience-bound access tokens. No external identity provider, open signup, organizations, or API keys.

Stack: Node ≥26 (native TypeScript execution), pnpm 12.3.4, Vite+ 0.3.1, TypeScript 7, Effect **4.0.0-rc.112**, Better Auth, `@better-auth/oauth-provider` and `@better-auth/cimd` **1.7.3**. The provider handles OAuth, password hashing, session cookies, signing keys, consent, refresh rotation, and revocation. Effect handles the shared typed HTTP API, configuration/schema boundaries, database transactions and process resource lifetime. `@effect/sql-sqlite-node` **4.0.0-rc.112** uses Node’s built-in SQLite for all persistent auth state; Better Auth shares that connection through a Kysely bridge.

## Develop locally

```sh
pnpm install --frozen-lockfile
vp run dev
```

Open http://localhost:3000 and create the owner account on first use. No `.env` or secret generation is needed. Development generates a random secret once in `.dev/secret` and stores its database in `.dev/auth.sqlite`; accounts and sessions persist across restarts. The `.dev/` directory is ignored by Git. To reset the local identity, stop development and delete `.dev/`.

The command builds the shared API once, then starts its compiler watcher, the server with automatic restarts, and the Vite website with hot reload. Vite proxies API, administration, discovery and health requests to `127.0.0.1:3001`; ports 3000 and 3001 must be available. Ctrl-C stops all three watchers. `pnpm dev` runs the same workflow.

Development uses fixed localhost configuration with its own secret and database regardless of `.env` or exported production settings. New databases start without resources; create them in the dashboard after signing in. Production startup still requires explicit configuration.

## Run the production build locally

```sh
cp .env.example .env
chmod 600 .env
# Edit .env: set BETTER_AUTH_SECRET to output from `openssl rand -hex 32`.
# Choose the canonical URL before issuing any tokens.
pnpm --filter @clankerauth/web exec playwright install chromium
pnpm ready
pnpm start
```

Open the configured `AUTH_BASE_URL`, create the owner account with an email and an 8–128 character password, then sign in. The sample uses loopback HTTP on port 3000; any non-loopback issuer **requires HTTPS**. `pnpm build` builds both workspace apps; `pnpm start` runs the packed server. `.agents/setup` installs/builds without creating credentials or identity state; it is not active for future orbs until committed changes reach the default branch.

## Workspace

The Vite+ monorepo conventions were generated in a safe scratch directory with
`vp create vite:monorepo --directory clankerauth-workspace-scaffold --no-agent --no-editor --no-git --no-hooks --package-manager pnpm --no-interactive`,
then integrated without replacing existing auth code or Git history. The workspace uses pnpm catalogs and Vite+ recursive task orchestration, following clanker-okf's conventions. No unused scaffold example packages are retained.

- `packages/api` (`@clankerauth/api`): shared Effect schemas and `HttpApi` contract for setup, resource and client administration, compiled to JavaScript and declarations. The server implements it with `HttpApiBuilder`; the browser derives its client with `HttpApiClient`. Better Auth retains its own client and handler for authentication/OAuth.
- `apps/server` (`@clankerauth/server`): native HTTP service, auth/configuration, first-run setup, SQLite integration tests and the optional MCP interoperability harness. `vp pack` emits `dist/main.mjs`.
- `apps/web` (`@clankerauth/web`): browser account setup, login, consent, resources and client access. Vite builds `dist`; the server resolves these assets through its workspace dependency, independent of its working directory.

The root owns orchestration and shared TypeScript/check configuration; package dependencies are pinned centrally in `pnpm-workspace.yaml`. `vp run -r build` builds the API contract before the browser and server, and the browser assets before the server. `vp run dev` and `pnpm check` build the contract first; development watches shared schemas and rebuilds them automatically. Tests exercise built browser assets, so run `pnpm build` before a standalone `pnpm test` on a fresh checkout. `pnpm ready` handles that ordering. Production packaging uses `pnpm --filter @clankerauth/server deploy --prod <directory>`; the result includes the packed server, browser assets and production dependency closure.

The scaffold's optional `vite-plus/prefer-vite-plus-imports` JavaScript lint plugin is omitted because Vite+ 0.3.1 crashes before analysis when loading it in this orb. Formatting, native lint rules, type-aware lint and TypeScript checking remain enabled.

The server automatically runs the version-pinned migrations before listening. A fresh database opens first-run setup; the first visitor to create an account becomes the sole owner. Complete setup on the private network before exposing the service more widely. No setup token is required. Account creation and the owner marker are committed together, and setup closes permanently after creation. It does not create a login session. Existing instances keep their owner and credentials; startup refuses inconsistent databases containing accounts without an owner marker. Run only one server instance against a database at a time.

First-run HTTP routes:

- `GET /api/setup`: returns `{required: boolean}` without account details.
- `POST /api/setup`: JSON `{email, password}` with the exact configured `Origin`; returns `201 {created: true}` without a session cookie. Invalid input returns 400, invalid origin returns 403, and completed setup returns 409.

## Configuration and trust boundaries

| Variable             | Meaning                                                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_BASE_URL`      | Stable HTTPS **origin**, no path/trailing slash. Private LAN/VPN DNS is fine.                                                |
| `BETTER_AUTH_SECRET` | At least 32 characters from a cryptographic RNG. Keep permanently with backups; encrypts signing material and signs cookies. |
| `AUTH_DATABASE`      | SQLite path; default `data/auth.sqlite`. Persist the whole directory.                                                        |
| `HOST`, `PORT`       | Bind address and port; defaults `127.0.0.1:3000`. Containers use `0.0.0.0:3000`.                                             |

The **issuer is `AUTH_BASE_URL/api/auth`**, not the origin alone. All integrations must pin that exact value. The server reconstructs requests from configured `AUTH_BASE_URL`, not `Host`, `Forwarded`, or `X-Forwarded-*`. Use one canonical hostname; proxies must not rewrite the public path. Only the canonical origin is trusted for account setup, owner login, consent and administrative writes. Browser cookies are HttpOnly, SameSite=Lax, and Secure on HTTPS. Mutating resource and client administration also requires a session established within the last 15 minutes.

Only explicitly mounted endpoints are reachable: native Better Auth account signup, generic JWT minting, and client/resource administrative routes are not exposed. Client administration uses owner-authenticated wrappers with fixed PKCE/consent/grant policy. Protocol endpoints and discovery allow non-credentialed CORS; login and owner administration do not.

The owner marker is the identity eligibility boundary, not merely an admin role. Existing non-owner accounts cannot log in or use old sessions for authorization, consent, continuation or password changes. Code exchange and refresh recheck the grant's user even without a browser session; UserInfo rejects ineligible users and introspection reports their JWT/refresh tokens inactive. Legacy records are retained, not silently deleted. Sign-out remains available to discard a legacy cookie. Setup creates the owner without a session; session creation requires the owner marker. Generic session JWT emission is explicitly disabled with `disableSettingJwtHeader`; `/get-session` returns no `set-auth-jwt` header. Public OAuth subject identifiers are used; pairwise subjects and machine grants are not configured.

Resources, their scopes, and client access are managed in the dashboard and stored in SQLite. A fresh database has no resources. Restarts retain dashboard changes; there are no environment seeds or configuration overrides. Resource identifiers are exact HTTPS audience URLs without fragments, queries or credentials. A resource owns its scope names: two resources can both define `read` with separate meaning and consent. See [domain language](docs/domain-language.md) for the shared vocabulary.

Downstream apps may delegate identity eligibility to this issuer's owner-only issuance policy; they do not need a separate configured owner ID or `sub` equality check. They must still verify the access token's signature, exact issuer, token type, expiry and their own resource audience, and enforce the required endpoint scopes. Resource registration alone does not grant access: the verified token must carry the required scopes. Keep `sub` for identity and audit attribution. This contract depends on owner-only issuance; adding other eligible users or grant types requires reviewing downstream access policy. Do not authorize by email or assume `email_verified` is true; this service has no email verification transport.

## Connect a client

For a compatible MCP client, paste the MCP server URL into the client, sign in as the owner, and approve the requested Resource and scopes. Create the Resource in this dashboard first and configure the MCP server to advertise this issuer. Client ID Metadata Documents (CIMD) and Dynamic Client Registration (DCR) let clients identify themselves without manually copying a client ID or callback URL.

Automatically onboarded clients may request any configured Resource's scopes, including Resources added later. Onboarding grants no access: owner login and resource-specific consent are required. Client names are supplied by clients; consent displays the actual identifier, CIMD metadata hostname when applicable, and callback destination. Review those alongside the requested scopes.

The dashboard lists managed, dynamically registered, and CIMD clients. **Revoke authorization** clears consent and renewal credentials while allowing a new consent flow. **Block client** additionally prevents authorization for that client ID until unblocked; blocking a CIMD client survives metadata rediscovery. Unblocking does not restore old grants. Existing JWTs at offline downstream verifiers may remain valid for up to five minutes. A block is specific to an identifier, not an attestation of the software or its operator.

### Managed registration

Sign in and create the protected Resources first, then use **Register client**. Supply **Client name**, **Exact redirect URI**, and select its **Allowed Resources**. Public desktop/native clients cannot keep secrets: select **Native / desktop client (loopback redirect)** and leave **Confidential client (can securely store a secret)** unchecked. Web backends can select confidential and securely store the one-time secret. Confidential clients use `client_secret_basic`; public clients use `none`. All clients require S256 PKCE and consent. Redirect validation comes from Better Auth (HTTPS for web, exact loopback/private-use schemes for native; loopback ports follow native-client rules).

A managed client can access multiple resources through its **Client access** settings. Automatically onboarded clients do not need manually assigned Resource access. Each authorization and token request still targets exactly one resource, with consent stored independently for that resource. Missing, repeated or multiple `resource` parameters are rejected. Scope changes take effect immediately for new requests and update linked clients' scope ceilings; newly added scopes require consent. Removing access clears that client's consent and outstanding grants for the removed resource. Re-adding access does not restore old codes or refresh tokens, and access to other resources remains intact. A resource cannot be deleted while managed clients still have access; remove those dependencies first. Automatic eligibility does not prevent deletion; deleting a Resource removes its stored authorization grants. To change a client redirect URI, delete and re-register. Secret rotation invalidates the previous secret immediately. Deleting a client removes its stored grants. Existing JWTs at offline downstream verifiers remain usable for at most five minutes.

Administrative HTTP routes (session cookie + exact `Origin`, never an API bearer token):

- `GET /admin/clients`: list clients, resources and `clientAccess: [{client_id, resource}]`.
- `POST /admin/clients`: `{name, redirect, resources: string[], native, confidential}`; returns client metadata and a one-time secret when confidential.
- `POST /admin/clients/access`: `{client_id, resources: string[]}`; replaces a managed client's resource access.
- `POST /admin/clients/revoke`: `{client_id}`; clears consent and stored grants.
- `POST /admin/clients/block`: `{client_id, blocked: boolean}`; blocks or unblocks the identifier, revoking stored authorization when blocked.
- `POST /admin/resources`: `{identifier, name, scopes: string[]}`; creates a resource.
- `POST /admin/resources/update`: `{identifier, name, scopes: string[]}`; updates its name and scopes, retaining its identifier.
- `POST /admin/resources/delete`: `{identifier}`; deletes an unlinked resource.
- `POST /admin/clients/rotate`: `{client_id}`; returns a new one-time secret.
- `POST /admin/clients/delete`: `{client_id}`.

## OAuth discovery, flow and lifecycle

For origin `https://auth.internal`:

| Endpoint                    | URL path                                                 |
| --------------------------- | -------------------------------------------------------- |
| RFC 8414 metadata           | `/.well-known/oauth-authorization-server/api/auth`       |
| Metadata alias              | `/api/auth/.well-known/oauth-authorization-server`       |
| OIDC discovery              | `/api/auth/.well-known/openid-configuration`             |
| Public signing keys         | `/api/auth/jwks`                                         |
| Authorization               | `/api/auth/oauth2/authorize`                             |
| Dynamic client registration | `/api/auth/oauth2/register`                              |
| Token exchange / refresh    | `/api/auth/oauth2/token`                                 |
| Revocation / introspection  | `/api/auth/oauth2/revoke`, `/api/auth/oauth2/introspect` |
| UserInfo                    | `/api/auth/oauth2/userinfo`                              |

1. Discover metadata from the pinned issuer. Use a HTTPS CIMD URL as `client_id` when supported, otherwise register through the advertised `registration_endpoint` (DCR), or use a managed client ID. Generate a random PKCE verifier and S256 challenge; retain verifier, state, and expected issuer in the client.
2. Navigate to `authorization_endpoint` with `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`, `scope`, and exactly one `resource`.
3. The owner logs in and accepts or denies the signed consent request. The browser client forwards Better Auth's signed OAuth query; do not construct consent requests from unsigned inputs.
4. On the client callback, verify **state and `iss`** before submitting the code. POST form-encoded `grant_type=authorization_code`, `client_id`, `redirect_uri`, `code`, `code_verifier`, and the same `resource` to the discovered token endpoint. Confidential clients also send HTTP Basic client authentication.
5. Send the access token in `Authorization: Bearer …` to the intended resource, never in a URL. Never send the ID token to an API.

`openid profile email` are optional identity scopes; resource-specific scopes carry API capabilities. `offline_access` requests a refresh token. JWT access tokens have `typ=at+jwt`, a five-minute maximum lifetime and the chosen resource audience. With `openid`, Better Auth additionally includes **its own UserInfo endpoint** in `aud`; no other downstream resource is added. An ID token is audience-bound to the OAuth client, not the API.

Authorization codes expire after 120 seconds and are one-time. Refresh tokens expire after 30 days, rotate on every use, and remain bound to their original resource/client. Reusing an old refresh token triggers family invalidation; no retry grace interval is enabled. Refresh using `grant_type=refresh_token`, `refresh_token`, `client_id`, the same `resource`, and the client's registered authentication method. Clients must serialize refresh and atomically replace their stored refresh token.

All online requests share one per-service FIFO execution lane, including token issuance, revocation and client deletion. This prevents concurrent redemption from bypassing Better Auth 1.7.3's already-revoked-token detection: a replay invalidates the winner's replacement too. The provider defines a family broadly as **all refresh grants for the same client ID and user ID**, across sessions/resources, plus associated opaque access rows. Concurrent revocation of an already-rotated parent also invalidates that family, although this provider version responds `400 invalid_request` in that case. Other clients' grants remain separate.

The pinned pnpm patch in `patches/@better-auth__oauth-provider@1.7.3.patch` makes the provider wait for both access-token signing and refresh writes to settle before propagating an issuance error. Without it, fail-fast `Promise.all` can release the execution lane while a replacement insert is still pending. The patch also checks a refresh token's client binding **before** revoked-token invalidation, preventing a rotated token from client A from deleting client B's family. It preserves provider cryptography and token formats. The lane and patch provide completion ordering, **not transaction rollback**; failed issuance may consume a code or leave a completed grant that later revocation/replay removes. Preserve and re-evaluate this patch on upgrades, running the controlled concurrency, cross-client revocation and injected-signing-failure regressions. Never run multiple processes/Service instances against this database or call raw `auth.handler`/`auth.api` concurrently outside the application's lane. Serialized execution favors safety over throughput; enforce abuse limits at the proxy. Graceful shutdown closes HTTP admission and drains admitted application work, including work from disconnected clients, before closing SQLite; late application admission receives 503.

POST form-encoded `token`, `token_type_hint=refresh_token`, and client authentication to the revocation endpoint to end a grant. A JWT cannot be individually revoked: Better Auth returns `400 unsupported_token_type` for a valid JWT revocation attempt. Offline verifiers can accept it until expiry. Ending the browser session makes session-bound JWTs inactive at introspection/UserInfo, but **offline_access refresh tokens can survive logout**; logout is not “revoke every app.” Use **Revoke authorization** to remove that application's stored grants, or **Block client** to prevent new authorization for its identifier as well. Confidential clients may introspect their own tokens; do not expose a confidential secret in a browser or assume an arbitrary client can inspect another client's tokens.

These identity and refresh checks cannot retract an already issued JWT at an offline downstream verifier. After installing this policy over legacy state, allow at most five minutes for access-token expiry, or temporarily isolate downstream resources and enforce the owner subject there. A valid signature alone never replaces downstream subject/audience/scope policy.

## Integrate a downstream JSON API or MCP server

Install Better Auth in the **resource server** and use its supported request verifier. For example:

```ts
import { requestToResourceInput, verifyAccessTokenRequest } from "better-auth/oauth2";

const claims = await verifyAccessTokenRequest(requestToResourceInput(request), {
  jwksUrl: "https://auth.internal/api/auth/jwks",
  verifyOptions: {
    issuer: "https://auth.internal/api/auth",
    audience: "https://okf.internal/mcp", // exact audience of THIS server
    algorithms: ["EdDSA"],
    typ: "at+jwt",
  },
  requiredScopes: ["okf:read"],
});
// Now enforce this app's user/action policy against claims.sub.
```

Pin issuer, audience and JWKS URL in trusted server configuration. Never derive them from unverified token claims. Validate signature, expiry, token type and scopes; reject opaque tokens and ID tokens for API access. The helper also validates DPoP-bound requests if a client opts into DPoP; multi-instance downstream services need a shared replay store and correctly reconstructed external request URLs. DPoP interoperability has not been independently exercised here.

For MCP, the **downstream MCP server**, not this identity service, hosts RFC 9728 protected-resource metadata and returns the bearer challenge:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://okf.internal/.well-known/oauth-protected-resource/mcp", scope="okf:read"
```

```json
{
  "resource": "https://okf.internal/mcp",
  "authorization_servers": ["https://auth.internal/api/auth"],
  "scopes_supported": ["okf:read", "okf:write"],
  "bearer_methods_supported": ["header"]
}
```

Return 401 for missing/invalid tokens, 403 with `insufficient_scope` and required scopes for insufficient access. Do not put `offline_access` in protected-resource scope requirements. Do not pass tokens through to unrelated services. `@better-auth/mcp` provides supported resource-server helpers such as `createMcpProtectedRequestHandler`; it is not installed here because this service does not host an MCP resource.

The service supports CIMD, DCR and managed pre-registration. CIMD metadata is fetched server-side using the provider's secure transport; private-address metadata hosts are not accepted. DCR is unauthenticated so compatible clients can onboard automatically. Registration is limited to 10 requests per minute per direct peer and 1,000 automatic client records. On new onboarding attempts, unblocked clients older than seven days with no stored consent, refresh grants, or pending authorization codes are removed; blocked identifiers are retained. Treat registration as untrusted metadata and apply registration abuse limits at the reverse proxy. The official MCP client SDK interoperability harness exercises real clanker-okf actions with isolated fake storage; see [reproduction and results](docs/mcp-interop.md). Named desktop MCP products still require validation in the target environment.

## Deployment, migrations and backups

Use trusted TLS behind a reverse proxy; distribute your private CA to every browser, client and resource-server runtime. Bind the backend only to the proxy network, firewall it from direct users, strip untrusted forwarding headers, disable request-body/cookie/Authorization/query logging, and do not cache auth responses. Enforce per-client-IP abuse limits at the proxy. The app rate-limits login (5/minute) and provider endpoints using the **direct socket peer**; behind one proxy this is a shared limit, not a trusted forwarded IP. Protect the origin from the public Internet unless you deliberately operate it as an Internet-facing identity service.

```sh
docker build -t clankerauth:local .
# Prepare .env.production: HTTPS URL, random secret, HOST=0.0.0.0,
# AUTH_DATABASE=/data/auth.sqlite. JSON values must not have outer shell quotes.
docker volume create clankerauth-data
docker run --name clankerauth --env-file .env.production -v clankerauth-data:/data \
  -p 127.0.0.1:3000:3000 --restart unless-stopped clankerauth:local
```

Open the configured HTTPS origin and create the owner account, then sign in and add Resources. Compatible MCP clients onboard when connecting; use managed registration for clients that require a preconfigured ID. The image runs as non-root; bind-mounted directories must be writable by UID 1000 with restrictive permissions. `/healthz` checks database connectivity. SQLite WAL is suitable for **one instance on a local persistent filesystem**, not NFS, autoscaling replicas or ephemeral serverless storage. Keep the SQLite database, WAL/SHM files and encryption secret persistent; the `jwks` table contains encrypted private signing keys. Do not regenerate the secret or delete signing rows on restart. No automatic signing-key rotation schedule is configured; plan deliberate rotation with an overlap window and verify every downstream JWKS cache before retiring old keys.

**Migrations:** startup invokes Better Auth's supported version-pinned migrator for core and provider tables plus the singleton owner marker before accepting HTTP requests. Migrations are repeatable; a migration failure stops startup. Before upgrading dependencies: stop the service, back up, rehearse startup against an isolated backup, run the complete tests, then start the upgraded service. Unsafe schema changes fail closed; do not force them past the migrator. Rollback requires the old code **and matching database backup**, not just an older image.

**Backup:** stop the single server cleanly, copy the entire database directory and `.env.production`/secret-manager version to encrypted restricted storage, then restart. For online backups use SQLite's backup API/tool, never copy only the live `.sqlite` file in WAL mode. Test restores regularly in an isolated network so the restored issuer cannot issue production credentials accidentally. A database backup contains sensitive identity/token state even though passwords/tokens are hashed and private keys are encrypted.

**Password recovery:** there is intentionally no forgotten-password flow, recovery endpoint or administration command. Keep the owner password in a password manager. Losing both the database and its secret requires restoring a matched backup or provisioning a new instance and re-enrolling all clients.

## Verification and limits

Install the browser used by the dashboard regression fixture once after dependency installation:

```sh
pnpm --filter @clankerauth/web exec playwright install chromium
```

The web workspace's `test` command runs Chromium against built assets with intercepted API responses; it never uses a real account or database. It covers committed mutations followed by failed dashboard reads, read-only refresh retries, form recovery and one-time credentials. Run it after building with `pnpm --filter @clankerauth/web test`. CI installs Chromium and its system dependencies before `pnpm ready`.

`pnpm ready` runs Vite+ formatting/type-aware lint/TypeScript checks, both production workspace builds, and real SQLite integration tests. Tests also cover automatic DCR/CIMD onboarding, metadata validation and changes, registration limits, client blocking and revocation. Browser fixtures exercise automatic-client controls and escaped consent identity details. Tests cover dashboard resource persistence and validation, multiple-resource client access, resource-specific consent, targeted access removal, automatic migrations, first-run setup, built workspace asset serving, owner login/logout, signup closure, legacy non-owner session/grant denial, CSRF, discovery, signed consent and login continuation, PKCE/redirect failures, audience isolation, JWT expiry, persisted keys/sessions, controlled concurrent refresh/revocation/deletion, cross-client revocation isolation, signing-failure draining, disconnected-client shutdown and atomic account creation. Chromium verification covers login/admin/consent against the service; delayed-response browser fixtures additionally check duplicate dashboard mutations and success/error control recovery without touching real registrations.

CI also packages and executes the production output from an unrelated working directory with a disposable database. Reproduce that smoke check after building:

```sh
package_dir="$(cd /tmp && pwd -P)/clankerauth-production"
pnpm --filter @clankerauth/server deploy --prod "$package_dir"
pnpm test:package "$package_dir"
```

It verifies automatic migration, setup before and after a fresh restart, owner login and session-header policy, browser assets, discovery, dashboard-created resource persistence, restart-persisted keys/session and permanent setup closure, then stops its child process and removes test state. This is not a Docker-runtime test. The smoke script never reads the preview `.env` or database.

This is a narrow single-owner initial service, not a multi-user IAM product or an OAuth conformance certification. Docker image execution, third-party MCP clients, DPoP, private-key-JWT clients and reverse-proxy/CA configurations require validation in the target environment. The provider's current bad-PKCE response is `401 invalid_request`; do not assume every OAuth failure has the same status. No external deployment, push or infrastructure mutation is part of this repository setup.

References checked against current docs and installed 1.7.3 types: [Better Auth OAuth Provider](https://www.better-auth.com/docs/plugins/oauth-provider), [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [MCP client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration), [Vite+ create](https://viteplus.dev/guide/create).
