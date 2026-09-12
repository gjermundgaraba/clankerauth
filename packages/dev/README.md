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

Each call listens on a random loopback port, creates a fresh SQLite database and secret in a temporary directory, provisions the owner, the resources and the client through the real endpoints, and returns. `close()` drains in-flight requests, closes the database and deletes the directory. Nothing is shared between calls and nothing survives them.

MIT licensed. The bundled third-party licenses are listed in `dist/THIRD_PARTY_NOTICES.txt`.
