# Clanker Auth

A single-instance, self-hosted identity and OAuth authorization server for private-network apps. Local password login, an offline-provisioned owner, explicit client registration, signed consent, S256 PKCE, and audience-bound access tokens. No external identity provider, open signup, dynamic registration, organizations, or API keys.

Stack: Node ≥26 (native TypeScript execution), pnpm 12.3.4, Vite+ 0.3.1, TypeScript 7, Effect **4.0.0-rc.112**, Better Auth and `@better-auth/oauth-provider` **1.7.3**. The provider handles OAuth, password hashing, session cookies, signing keys, consent, refresh rotation, and revocation. Effect handles configuration/schema boundaries and process resource lifetime. SQLite via the provider-supported better-sqlite3 12 line owns all persistent auth state.

## Start locally

```sh
pnpm install --frozen-lockfile
cp .env.example .env
chmod 600 .env
# Edit .env: set BETTER_AUTH_SECRET to output from `openssl rand -hex 32`.
# Choose the canonical URL and resource policy before issuing any tokens.
pnpm auth:admin migrate
# Supply a 16–128 character password on stdin from a password manager or mode-600 file.
pnpm auth:admin bootstrap owner@example.internal < /secure/owner-password
pnpm ready
pnpm start
```

Open the configured `AUTH_BASE_URL`. For local development the sample uses loopback HTTP on port 3000; any non-loopback issuer **requires HTTPS**. `pnpm build` builds both workspace apps; `pnpm start` runs the packed server. `pnpm dev` runs the server TypeScript source against the built browser app (rebuild after browser edits, restart after server edits). Both use the same canonical origin and routes. `.agents/setup` installs/builds without creating credentials or identity state; it is not active for future orbs until committed changes reach the default branch.

## Workspace

The Vite+ monorepo conventions were generated in a safe scratch directory with
`vp create vite:monorepo --directory clankerauth-workspace-scaffold --no-agent --no-editor --no-git --no-hooks --package-manager pnpm --no-interactive`,
then integrated without replacing existing auth code or Git history. The workspace uses pnpm catalogs and Vite+ recursive task orchestration, following clanker-okf's conventions. No unused scaffold example packages are retained.

- `apps/server` (`@clankerauth/server`): native HTTP service, auth/configuration, offline administration, SQLite integration tests and the optional MCP interoperability harness. `vp pack` emits `dist/main.mjs` and `dist/admin.mjs`.
- `apps/web` (`@clankerauth/web`): browser login, consent and client administration. Vite builds `dist`; the server resolves these assets through its workspace dependency, independent of its working directory.

The root owns orchestration and shared TypeScript/check configuration; package dependencies are pinned centrally in `pnpm-workspace.yaml`. `vp run -r build` orders the browser build before the server. Tests exercise built browser assets, so run `pnpm build` before a standalone `pnpm test` on a fresh checkout. `pnpm ready` handles that ordering. `pnpm auth:admin` continues to work from source without a build prerequisite. Production packaging uses `pnpm --filter @clankerauth/server deploy --prod <directory>`; the result includes the packed server, browser assets and production dependency closure.

The scaffold's optional `vite-plus/prefer-vite-plus-imports` JavaScript lint plugin is omitted because Vite+ 0.3.1 crashes before analysis when loading it in this orb. Formatting, native lint rules, type-aware lint and TypeScript checking remain enabled.

The server refuses to listen until migrations and owner bootstrap are complete. Bootstrap is an **offline command**, not an HTTP endpoint. It refuses any database that already contains accounts. Run only one server or maintenance command against a database at a time. If bootstrap is interrupted before the owner marker is written, restore the pre-bootstrap database and repeat; do not delete a database that has subsequently issued credentials.

## Configuration and trust boundaries

| Variable             | Meaning                                                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_BASE_URL`      | Stable HTTPS **origin**, no path/trailing slash. Private LAN/VPN DNS is fine.                                                |
| `BETTER_AUTH_SECRET` | At least 32 characters from a cryptographic RNG. Keep permanently with backups; encrypts signing material and signs cookies. |
| `AUTH_DATABASE`      | SQLite path; default `data/auth.sqlite`. Persist the whole directory.                                                        |
| `AUTH_RESOURCES`     | JSON array of `{identifier, name, scopes}`. Exact HTTPS identifiers, no fragments/query/credentials.                         |
| `HOST`, `PORT`       | Bind address and port; defaults `127.0.0.1:3000`. Containers use `0.0.0.0:3000`.                                             |

The **issuer is `AUTH_BASE_URL/api/auth`**, not the origin alone. All integrations must pin that exact value. The server reconstructs requests from configured `AUTH_BASE_URL`, not `Host`, `Forwarded`, or `X-Forwarded-*`. Use one canonical hostname; proxies must not rewrite the public path. Only the canonical origin is trusted for owner login, consent and administrative writes. Browser cookies are HttpOnly, SameSite=Lax, and Secure on HTTPS. Mutating client administration also requires a session established within the last 15 minutes.

Only explicitly mounted endpoints are reachable: native Better Auth account signup, generic JWT minting, and client/resource administrative routes are not exposed. Client administration uses owner-authenticated wrappers with fixed PKCE/consent/grant policy. Protocol endpoints and discovery allow non-credentialed CORS; login and owner administration do not.

The owner marker is the identity eligibility boundary, not merely an admin role. Existing non-owner accounts cannot log in or use old sessions for authorization, consent, continuation or password changes. Code exchange and refresh recheck the grant's user even without a browser session; UserInfo rejects ineligible users and introspection reports their JWT/refresh tokens inactive. Legacy records are retained, not silently deleted. Sign-out remains available to discard a legacy cookie. Session creation is permitted before the owner marker exists only in the offline bootstrap instance. Generic session JWT emission is explicitly disabled with `disableSettingJwtHeader`; `/get-session` returns no `set-auth-jwt` header. Public OAuth subject identifiers are used; pairwise subjects and machine grants are not configured.

Resource configuration is authoritative on restart. Configured resources overwrite their persisted policy; removed identifiers immediately stop passing this service's issuance/refresh allowlist. Already issued JWTs still live until expiry. Resources are not permission grants: each downstream app must map `sub` to its own access policy and enforce endpoint scopes. Do not authorize by email or assume `email_verified` is true; this service has no email verification transport.

## Register a client

Sign in, then use **Add an application**. Supply a name, exact redirect URI, one resource, and the client type. Public desktop/native clients cannot keep secrets: select native and leave confidential unchecked. Web backends can select confidential and securely store the one-time secret. Confidential clients use `client_secret_basic`; public clients use `none`. All clients require S256 PKCE and consent. Redirect validation comes from Better Auth (HTTPS for web, exact loopback/private-use schemes for native; loopback ports follow native-client rules).

Each registration links **one** resource and its configured scope ceiling. Register a separate client ID for a different resource, even if the same application consumes both. No client may request an unrelated resource, no token request may omit `resource`, and repeated/multiple resources are rejected. This deliberately favors explicit administration over universal bearer authority. To change redirect/resource policy, delete and re-register. Secret rotation invalidates the previous secret immediately. Deleting a client removes its stored grants; offline JWT verification still accepts existing access tokens for at most five minutes.

Administrative HTTP routes (session cookie + exact `Origin`, never an API bearer token):

- `GET /admin/clients`: list clients and configured resources.
- `POST /admin/clients`: `{name, redirect, resource, native, confidential}`; returns client metadata and a one-time secret when confidential.
- `POST /admin/clients/rotate`: `{client_id}`; returns a new one-time secret.
- `POST /admin/clients/delete`: `{client_id}`.

## OAuth discovery, flow and lifecycle

For origin `https://auth.internal`:

| Endpoint                   | URL path                                                 |
| -------------------------- | -------------------------------------------------------- |
| RFC 8414 metadata          | `/.well-known/oauth-authorization-server/api/auth`       |
| Metadata alias             | `/api/auth/.well-known/oauth-authorization-server`       |
| OIDC discovery             | `/api/auth/.well-known/openid-configuration`             |
| Public signing keys        | `/api/auth/jwks`                                         |
| Authorization              | `/api/auth/oauth2/authorize`                             |
| Token exchange / refresh   | `/api/auth/oauth2/token`                                 |
| Revocation / introspection | `/api/auth/oauth2/revoke`, `/api/auth/oauth2/introspect` |
| UserInfo                   | `/api/auth/oauth2/userinfo`                              |

1. Discover metadata from the pinned issuer. Generate a random PKCE verifier and S256 challenge; retain verifier, state, and expected issuer in the client.
2. Navigate to `authorization_endpoint` with `response_type=code`, registered `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`, `scope`, and exactly one `resource`.
3. The owner logs in and accepts or denies the signed consent request. The browser client forwards Better Auth's signed OAuth query; do not construct consent requests from unsigned inputs.
4. On the client callback, verify **state and `iss`** before submitting the code. POST form-encoded `grant_type=authorization_code`, `client_id`, `redirect_uri`, `code`, `code_verifier`, and the same `resource` to the discovered token endpoint. Confidential clients also send HTTP Basic client authentication.
5. Send the access token in `Authorization: Bearer …` to the intended resource, never in a URL. Never send the ID token to an API.

`openid profile email` are optional identity scopes; resource-specific scopes carry API capabilities. `offline_access` requests a refresh token. JWT access tokens have `typ=at+jwt`, a five-minute maximum lifetime and the chosen resource audience. With `openid`, Better Auth additionally includes **its own UserInfo endpoint** in `aud`; no other downstream resource is added. An ID token is audience-bound to the OAuth client, not the API.

Authorization codes expire after 120 seconds and are one-time. Refresh tokens expire after 30 days, rotate on every use, and remain bound to their original resource/client. Reusing an old refresh token triggers family invalidation; no retry grace interval is enabled. Refresh using `grant_type=refresh_token`, `refresh_token`, `client_id`, the same `resource`, and the client's registered authentication method. Clients must serialize refresh and atomically replace their stored refresh token.

All online requests share one per-service FIFO execution lane, including token issuance, revocation and client deletion. This prevents concurrent redemption from bypassing Better Auth 1.7.3's already-revoked-token detection: a replay invalidates the winner's replacement too. The provider defines a family broadly as **all refresh grants for the same client ID and user ID**, across sessions/resources, plus associated opaque access rows. Concurrent revocation of an already-rotated parent also invalidates that family, although this provider version responds `400 invalid_request` in that case. Other clients' grants remain separate.

The pinned pnpm patch in `patches/@better-auth__oauth-provider@1.7.3.patch` makes the provider wait for both access-token signing and refresh writes to settle before propagating an issuance error. Without it, fail-fast `Promise.all` can release the execution lane while a replacement insert is still pending. The patch also checks a refresh token's client binding **before** revoked-token invalidation, preventing a rotated token from client A from deleting client B's family. It preserves provider cryptography and token formats. The lane and patch provide completion ordering, **not transaction rollback**; failed issuance may consume a code or leave a completed grant that later revocation/replay removes. Preserve and re-evaluate this patch on upgrades, running the controlled concurrency, cross-client revocation and injected-signing-failure regressions. Never run multiple processes/Service instances against this database or call raw `auth.handler`/`auth.api` concurrently outside the application's lane. Offline maintenance must run while the server is stopped. Serialized execution favors safety over throughput; enforce abuse limits at the proxy. Graceful shutdown closes HTTP admission and drains admitted application work, including work from disconnected clients, before closing SQLite; late application admission receives 503.

POST form-encoded `token`, `token_type_hint=refresh_token`, and client authentication to the revocation endpoint to end a grant. A JWT cannot be individually revoked: Better Auth returns `400 unsupported_token_type` for a valid JWT revocation attempt. Offline verifiers can accept it until expiry. Ending the browser session makes session-bound JWTs inactive at introspection/UserInfo, but **offline_access refresh tokens can survive logout**; logout is not “revoke every app.” Delete a client or use offline recovery for a broader cutoff. Confidential clients may introspect their own tokens; do not expose a confidential secret in a browser or assume an arbitrary client can inspect another client's tokens.

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

The current **MCP 2026-07-28** specification recommends Client ID Metadata Documents (CIMD), accepts pre-registration, and deprecates unrestricted DCR in favor of CIMD. This initial service intentionally supports **pre-registration only**. A client must accept a preconfigured client ID/redirect URI; clients requiring automatic CIMD/DCR will not work unchanged. Automatic URL-based discovery also introduces outbound-fetch trust decisions that this private service does not need yet. The official MCP client SDK has been tested end to end against real clanker-okf actions through an isolated resource-verifier harness with fake storage; see [reproduction and results](docs/mcp-interop.md). This is prototype integration, not authentication shipped in clanker-okf or verification of a named desktop MCP product.

## Deployment, migrations and recovery

Use trusted TLS behind a reverse proxy; distribute your private CA to every browser, client and resource-server runtime. Bind the backend only to the proxy network, firewall it from direct users, strip untrusted forwarding headers, disable request-body/cookie/Authorization/query logging, and do not cache auth responses. Enforce per-client-IP abuse limits at the proxy. The app rate-limits login (5/minute) and provider endpoints using the **direct socket peer**; behind one proxy this is a shared limit, not a trusted forwarded IP. Protect the origin from the public Internet unless you deliberately operate it as an Internet-facing identity service.

```sh
docker build -t clankerauth:local .
# Prepare .env.production: HTTPS URL, random secret, resources, HOST=0.0.0.0,
# AUTH_DATABASE=/data/auth.sqlite. JSON values must not have outer shell quotes.
docker volume create clankerauth-data
docker run --rm --env-file .env.production -v clankerauth-data:/data \
  clankerauth:local node dist/admin.mjs migrate
docker run --rm -i --env-file .env.production -v clankerauth-data:/data \
  clankerauth:local node dist/admin.mjs bootstrap owner@example.internal < /secure/owner-password
docker run --name clankerauth --env-file .env.production -v clankerauth-data:/data \
  -p 127.0.0.1:3000:3000 --restart unless-stopped clankerauth:local
```

The image runs as non-root; bind-mounted directories must be writable by UID 1000 with restrictive permissions. `/healthz` checks database connectivity. SQLite WAL is suitable for **one instance on a local persistent filesystem**, not NFS, autoscaling replicas or ephemeral serverless storage. Keep the SQLite database, WAL/SHM files and encryption secret persistent; the `jwks` table contains encrypted private signing keys. Do not regenerate the secret or delete signing rows on restart. No automatic signing-key rotation schedule is configured; plan deliberate rotation with an overlap window and verify every downstream JWKS cache before retiring old keys.

**Migrations:** `pnpm auth:admin migrate` invokes Better Auth's supported version-pinned migrator for core and provider tables plus the singleton owner marker. It is repeatable and does not run at server startup. Before upgrading dependencies: stop the service, back up, rehearse migration against a backup, run the complete tests, migrate, then start. Unsafe schema changes fail closed; do not force them past the migrator. Rollback requires the old code **and matching database backup**, not just an older image.

**Backup:** stop the single server cleanly, copy the entire database directory and `.env.production`/secret-manager version to encrypted restricted storage, then restart. For online backups use SQLite's backup API/tool, never copy only the live `.sqlite` file in WAL mode. Test restores regularly in an isolated network so the restored issuer cannot issue production credentials accidentally. A database backup contains sensitive identity/token state even though passwords/tokens are hashed and private keys are encrypted.

**Lost owner password:** stop the service, back up, then run:

```sh
pnpm auth:admin recover < /secure/new-owner-password
# Container equivalent (with the main container stopped):
docker run --rm -i --env-file .env.production -v clankerauth-data:/data \
  clankerauth:local node dist/admin.mjs recover < /secure/new-owner-password
```

Recovery uses Better Auth's password hasher and atomically updates the credential and clears all sessions, verification challenges, OAuth consents, access-token records and refresh grants. Clients and signing keys remain. Offline JWTs can still be accepted for five minutes; for a compromise, isolate downstream resources during that window. Recovery requires filesystem/operator authority and has no HTTP backdoor, recovery code or email dependency. Losing both the database and its secret is not recoverable; restore the matched backup or re-provision and re-enroll all clients. An interrupted first bootstrap should be recovered from its pre-bootstrap backup.

## Verification and limits

`pnpm ready` runs Vite+ formatting/type-aware lint/TypeScript checks, both production workspace builds, and real SQLite integration tests. Tests cover built workspace asset serving, owner login/logout, signup closure, legacy non-owner session/grant denial, CSRF, discovery, signed consent and login continuation, PKCE/redirect failures, audience isolation, JWT expiry, persisted keys/sessions, controlled concurrent refresh/revocation/deletion, cross-client revocation isolation, signing-failure draining, disconnected-client shutdown and offline recovery. Chromium verification covers login/admin/consent against the service; delayed-response browser fixtures additionally check duplicate dashboard mutations and success/error control recovery without touching real registrations.

CI also packages and executes the production output from an unrelated working directory with a disposable database. Reproduce that smoke check after building:

```sh
pnpm --filter @clankerauth/server deploy --prod /tmp/clankerauth-production
pnpm test:package /tmp/clankerauth-production
```

It verifies migration/bootstrap, owner login and session-header policy, browser assets, discovery, restart-persisted keys/session and offline recovery, then stops its child process and removes test state. This is not a Docker-runtime test. The smoke script never reads the preview `.env` or database.

This is a narrow single-owner initial service, not a multi-user IAM product or an OAuth conformance certification. Docker image execution, third-party MCP clients, DPoP, private-key-JWT clients and reverse-proxy/CA configurations require validation in the target environment. The provider's current bad-PKCE response is `401 invalid_request`; do not assume every OAuth failure has the same status. No external deployment, push or infrastructure mutation is part of this repository setup.

References checked against current docs and installed 1.7.3 types: [Better Auth OAuth Provider](https://www.better-auth.com/docs/plugins/oauth-provider), [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [MCP client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration), [Vite+ create](https://viteplus.dev/guide/create).
