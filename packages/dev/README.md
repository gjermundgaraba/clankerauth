# @gjermundgaraba/clankerauth-dev

A disposable [Clanker Auth](https://github.com/gjermundgaraba/clankerauth) issuer for developing and testing applications that authenticate against one. The package bundles the whole server and dashboard with no dependencies, so it needs only Node 26 or newer.

It is published to GitHub Packages, which needs a GitHub token with the `read:packages` scope even for public packages. Map the scope in the project `.npmrc` and keep the credential in your user-level `~/.npmrc`, because pnpm ignores environment-expanded credentials in a project file:

```sh
echo '@gjermundgaraba:registry=https://npm.pkg.github.com' >> .npmrc
echo '//npm.pkg.github.com/:_authToken=${GH_TOKEN}' >> ~/.npmrc
npm install --save-dev @gjermundgaraba/clankerauth-dev
```

```ts
import { startDisposableIssuer } from "@gjermundgaraba/clankerauth-dev";

const issuer = await startDisposableIssuer({
  resources: [
    { identifier: "http://127.0.0.1:8080/mcp", name: "Notes MCP", scopes: ["notes:read"] },
  ],
  client: {
    name: "Notes console",
    redirect: "http://localhost:5173/callback",
    resources: ["http://127.0.0.1:8080/mcp"],
  },
});

issuer.issuer; // OAuth issuer URL, for discovery and token verification
issuer.url; // dashboard origin, sign in with issuer.owner.email and issuer.owner.password
issuer.clientId; // a confidential native client for the given redirect and resources
issuer.clientSecret;

await issuer.close();
```

Each call listens on a random loopback port, creates a fresh SQLite database and secret in a temporary directory, provisions the owner, the resources and the client through the real endpoints, and returns. The client is first party: once the owner is signed in, an authorization request redirects straight to the callback with a code and no consent step. `close()` drains in-flight requests, closes the database and deletes the directory. Nothing is shared between calls and nothing survives them.

Two optional test hooks: `cimdTransport` replaces the outbound fetch of CIMD client metadata so a test can serve fixture documents, and `onRequest` observes the method and URL of every incoming request.

Two optional test hooks help exercise integrations:

- `cimdTransport(input, init)` replaces outbound Client ID Metadata Document retrieval and returns a `Response` or `Promise<Response>`. Its arguments match `fetch`. Use it to serve fixture metadata for HTTPS client IDs without an external server. When omitted, the issuer uses its secure metadata transport.
- `onRequest({ method, url })` observes actual incoming HTTP requests at the issuer listener, including setup, discovery, JWKS, dynamic client registration, and token requests. `url` is a `URL`; headers and bodies are never passed. The callback runs synchronously before handling each request. A thrown error makes that request fail with HTTP 500, so keep observers nonthrowing.

MIT licensed. The bundled third-party licenses are listed in `dist/THIRD_PARTY_NOTICES.txt`.
