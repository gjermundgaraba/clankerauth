# MCP interoperability

The interoperability runner exercises clanker-okf's shipped HTTP authentication
with clankerauth and the official MCP SDK. It uses temporary auth state and fake
Code Storage; no production credentials, `.env`, or deployed services are used.

## Run

Build both repositories first. Use a Node runtime with native `Temporal`
(required by clanker-okf; confirm with `node -p 'typeof Temporal'`). The runner
fails early if the selected runtime lacks it. Supply a separate fixture directory containing
`@modelcontextprotocol/client@2.0.0` and `tsx`:

```sh
pnpm ready
pnpm --dir ../clanker-okf exec vp run ready
mkdir -p /tmp/okf-oauth-sdk
pnpm --dir /tmp/okf-oauth-sdk add @modelcontextprotocol/client@2.0.0 tsx
pnpm test:interop ../clanker-okf /tmp/okf-oauth-sdk
```

`apps/server/scripts/mcp-interop.mjs` invokes this repository's
`apps/server/scripts/oauth-interop.mjs`, loading the supplied clanker-okf
checkout's real HTTP server, typed client, and fake storage adapter. The harness
belongs here so its discovery assertions evolve with this issuer.

## Coverage

The official SDK discovers the protected Resource and issuer, automatically
registers a client through DCR, follows owner login and signed consent, exchanges
an S256 PKCE code, and calls the real MCP server. A separate CIMD client uses an
HTTPS metadata identifier without pre-registration and makes an authenticated
MCP call and rotates its refresh token. It asserts that the CIMD flow makes no
DCR registration and that the access token carries the metadata URL as client ID.
Tests also cover resource audiences, missing and invalid tokens,
insufficient scopes, callback issuer validation, and refresh rotation.

Ordinary server tests separately cover onboarding policy, metadata rejection,
client blocking and revocation, resource changes, and registration limits.
Browser tests exercise the shipped consent and administration UI.

## Boundaries

The harness substitutes local listeners for reserved HTTPS Resource URLs and an
injected transport for a fixed CIMD metadata fixture. Production CIMD uses the
provider's secure Node transport with public-address validation and DNS pinning.
The metadata URL must be reachable over public HTTPS, with only public addresses
in the issuer's DNS view; private split-DNS answers remain rejected.
This test does not certify private DNS, VPN routing, TLS trust, a named desktop
client, live Code Storage, or deployment. It does exercise the actual resource
server's token and scope enforcement, without the historical prototype proxy.
