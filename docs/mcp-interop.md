# Official MCP SDK / clanker-okf prototype interoperability

Verified on 2026-09-08 against clanker-okf's remote `origin/main` at
[`db488828904d6eae627a088bfe5a41e8429414a1`](https://github.com/gjermundgaraba/clanker-okf/commit/db488828904d6eae627a088bfe5a41e8429414a1),
using official `@modelcontextprotocol/client@2.0.0`, its Streamable HTTP transport,
OAuth orchestrator and PKCE implementation, and clanker-okf's actual HTTP/MCP server.

**This is prototype integration, not authentication shipped in clanker-okf.** That
checkout's `/mcp` is unauthenticated. The optional harness installs an independent
resource verifier/challenge layer in front of the real server, uses clanker-okf's
own fake Code Storage adapter, and counts every forwarded request and store-method
invocation. It does not treat attaching a token to the unprotected server as success.

## Reproduce

Run from the clankerauth repository, with Node ≥26 and pnpm available:

```sh
pnpm install --frozen-lockfile
git clone https://github.com/gjermundgaraba/clanker-okf.git /tmp/clankerauth-okf-interop
git -C /tmp/clankerauth-okf-interop checkout db488828904d6eae627a088bfe5a41e8429414a1
pnpm --dir /tmp/clankerauth-okf-interop install --frozen-lockfile
pnpm --dir /tmp/clankerauth-okf-interop add -Dw @modelcontextprotocol/client@2.0.0
pnpm --dir /tmp/clankerauth-okf-interop exec vp run -r build
pnpm test:interop /tmp/clankerauth-okf-interop
```

The SDK installation modifies only the temporary clone's dependency manifests, not
its server code. The harness lives in `apps/server/scripts/mcp-interop.mjs` and imports
the server workspace source. Remove the temporary clone after testing. The harness closes all
listeners and removes its temporary auth database and fake storage in `finally`.
It does not load `.env`, reuse preview accounts/clients, or instantiate the real
Code Storage client. It is intentionally outside `pnpm test`: normal unit tests
must not clone another repository or require network package installation.

## Decisive results

The command exits 0 and prints:

```text
PASS missing/invalid tokens: HTTP 401; forwarded=0; storageCalls=0
PASS official SDK challenge -> resource metadata -> issuer discovery -> owner login/consent -> S256 exchange
PASS real clanker-okf tools/list (14 tools), create_bundle and list_repos => {repos:["interop"]}; JWKS fetched
PASS validly signed wrong-audience token and tampered JWT: HTTP 401; zero additional forwarding/storage execution
PASS read-only token cannot execute create_bundle: HTTP 403 insufficient_scope; zero additional forwarding/storage execution
PASS official SDK refresh rotation followed by authenticated real MCP action
PROTOTYPE INTEGRATION PASSED; no shipped clanker-okf auth, real storage credentials, or preview state used
```

The initial unauthenticated SDK connection consumes the wrapper's `WWW-Authenticate`
challenge, discovers RFC 9728 protected-resource metadata and clankerauth's RFC 8414
metadata, and starts authorization using a pre-registered public client. The harness
submits local-owner login and signed consent over HTTP. The SDK exchanges the result
using its own saved PKCE verifier and checks callback `iss`. A deliberately wrong
callback issuer is rejected **before any token-endpoint request**.

The verifier pins the discovered issuer, JWKS URL, `EdDSA`, `typ=at+jwt`, the exact
resource audience and required scopes. Its small prototype access policy permits
only the isolated test owner's `sub`; read operations require `okf:read` and the
three mutating tools require `okf:write`. Authentication failure returns before any
forwarding. A valid token creates `interop/proof` in fake storage, and a separate
MCP read returns exactly `{repos:["interop"]}`. The negative tests use the real
mutating MCP request, including a correctly signed token issued for another audience
and a correctly signed read-only token. Both counters must remain unchanged.

## What this does not establish

- No named desktop product (Claude Desktop, Cursor, etc.) was tested. This is an
  actual official SDK client, not external-product compatibility certification.
- The owner interaction is scripted HTTP login/consent, not a browser-driven run
  inside a desktop MCP client. The service's browser UI was tested separately.
- Reserved HTTPS resource identities are mapped by the SDK's custom fetch option
  to a real loopback HTTP listener. Authorization-server discovery/token exchange,
  JWKS fetching, and MCP requests use actual HTTP. Private DNS, TLS certificates,
  VPN routing, browser CORS and private-CA trust are not validated by this mapping.
- No DCR/CIMD, DPoP, live Code Storage, Docker runtime or production writes are
  involved. The second resource's metadata is a test fixture used to obtain the
  wrong-audience token; the tested MCP resource's metadata is served over HTTP.
- The verifier is a test harness, not a hardened deployable reverse proxy. A real
  downstream integration must prevent direct access to the unprotected upstream,
  define its own user/action policy, propagate identity for auditing, and handle
  deployment-specific transports and revocation requirements.

The result establishes that the current provider and official SDK agree on the
pre-registered OAuth flow, resource audience, JWKS, refresh tokens and real MCP
messages. It does not change clanker-okf's existing authentication boundary.
