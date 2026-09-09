# MCP interoperability

The interoperability runner exercises clanker-okf's shipped HTTP authentication
with clankerauth and the official MCP SDK. It uses temporary auth state and fake
Code Storage; no production credentials, `.env`, or deployed services are used.

## Run

Build both repositories first. Supply a separate fixture directory containing
`@modelcontextprotocol/client@2.0.0` and `tsx`:

```sh
pnpm ready
pnpm --dir ../clanker-okf exec vp run ready
mkdir -p /tmp/okf-oauth-sdk
pnpm --dir /tmp/okf-oauth-sdk add @modelcontextprotocol/client@2.0.0 tsx
pnpm test:interop ../clanker-okf /tmp/okf-oauth-sdk
```

`apps/server/scripts/mcp-interop.mjs` invokes the downstream harness at
`packages/cli/tests/oauth-interop.mjs`. Both checkouts must contain automatic
onboarding support. See that checkout's `packages/cli/tests/oauth-interop.md`
for detailed coverage and fixture setup.

## Coverage

The official SDK discovers the protected Resource and issuer, automatically
registers a client through DCR, follows owner login and signed consent, exchanges
an S256 PKCE code, and calls the real MCP server. A separate CIMD client uses an
HTTPS metadata identifier without pre-registration and makes an authenticated
MCP call. Tests also cover resource audiences, missing and invalid tokens,
insufficient scopes, callback issuer validation, and refresh rotation.

Ordinary server tests separately cover onboarding policy, metadata rejection,
client blocking and revocation, resource changes, and registration limits.
Browser tests exercise the shipped consent and administration UI.

## Boundaries

The harness substitutes local listeners for reserved HTTPS Resource URLs and an
injected transport for a fixed CIMD metadata fixture. Production CIMD uses the
provider's secure Node transport with public-address validation and DNS pinning.
This test does not certify private DNS, VPN routing, TLS trust, a named desktop
client, live Code Storage, or deployment. It does exercise the actual resource
server's token and scope enforcement, without the historical prototype proxy.
