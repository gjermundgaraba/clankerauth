# @gjermundgaraba/clankerauth-dev

A disposable [Clanker Auth](https://github.com/gjermundgaraba/clankerauth) issuer for developing and testing applications that authenticate against one. The package bundles the whole server and dashboard with no dependencies, so it needs only Node 26 or newer.

```sh
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

Each call listens on a random loopback port, creates a fresh SQLite database and secret in a temporary directory, provisions the owner, the resources and the client in-process through the server's administration module, and returns. Only the returned issuer is reached over HTTP. The client is first party: once the owner is signed in, an authorization request redirects straight to the callback with a code and no consent step. `close()` drains in-flight requests, closes the database and deletes the directory. Nothing is shared between calls and nothing survives them.

Two optional test hooks help exercise integrations:

- `cimdTransport(input, init)` replaces outbound Client ID Metadata Document retrieval and returns a `Response` or `Promise<Response>`. Its arguments match `fetch`. Use it to serve fixture metadata for HTTPS client IDs without an external server. When omitted, the issuer uses its secure metadata transport.
- `onRequest({ method, url })` observes actual incoming HTTP requests at the issuer listener, such as discovery, JWKS, dynamic client registration, and token requests. Provisioning is in-process, so the observer sees only the test's own traffic. `url` is a `URL`; headers and bodies are never passed. The callback runs synchronously before handling each request. A thrown error makes that request fail with HTTP 500, so keep observers nonthrowing.

MIT licensed. The bundled third-party licenses are listed in `dist/THIRD_PARTY_NOTICES.txt`.
