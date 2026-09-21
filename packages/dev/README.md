# @gjermundgaraba/clankerauth-dev

A disposable [Clanker Auth](https://github.com/gjermundgaraba/clankerauth) issuer for developing and testing applications that authenticate against one. The package bundles the whole server and dashboard with no dependencies, so it needs only Node 26 or newer.

```sh
npm install --save-dev @gjermundgaraba/clankerauth-dev
```

```ts
import { startDisposableIssuer } from "@gjermundgaraba/clankerauth-dev";

const issuer = await startDisposableIssuer({
  resources: [{ identifier: "http://127.0.0.1:8080/", name: "Notes", scopes: ["notes:read"] }],
  client: {
    name: "Notes console",
    redirect: "http://localhost:5173/callback",
    resources: ["http://127.0.0.1:8080/"],
  },
});

issuer.issuer; // OAuth issuer URL, for discovery and token verification
issuer.url; // dashboard origin, sign in with issuer.owner.email and issuer.owner.password
issuer.clientId; // a confidential native client for the given redirect and resources
issuer.clientSecret;

await issuer.close();
```

Each call listens on a random loopback port, creates a fresh SQLite database and secret in a temporary directory, provisions the owner, the resources and the client in-process through the server's administration module, and returns. Only the returned issuer is reached over HTTP. The client is first party: once the owner is signed in, an authorization request redirects straight to the callback with a code and no consent step. `close()` drains in-flight requests, closes the database and deletes the directory. Nothing is shared between calls and nothing survives them.

## Provisioning

The issuer provisions what a test or a development script would otherwise script by hand against its HTTP API:

```ts
const key = await issuer.apiKey({ permissions: { [resource.identifier]: ["notes:read"] } });

// Needs a cookieDomain: the forward cookie is what a browser holds.
const { cookie, cookies } = await issuer.ownerSession("http://app.notes.localhost:5173");
const token = await issuer.ownerToken({
  resource: resource.identifier,
  appOrigin: "http://app.notes.localhost:5173",
});
```

`apiKey` returns the secret once. `ownerSession` signs the owner in and seals the forward cookie exactly as `/forward-auth/continue` does for a browser; `cookies` is the name/value form a browser-automation context takes. `ownerToken` runs the same forward-auth check and returns the access token, so a test never assembles a cookie jar.

## A workspace that survives a restart

Pass `dataDir` and a fixed `port` to keep the issuer's state:

```ts
const issuer = await startDisposableIssuer({ ...options, dataDir: ".dev/auth", port: 5174 });
```

The owner account and password, the signing secret, the registered client and the database are kept in that directory, and provisioning is idempotent, so the next start reuses them: the same sign-in works, API keys minted before still verify, and browser storage keyed by the origin survives. A fixed port is part of that, because the origin is what cookies and registered redirect URIs are keyed by. `close()` leaves the directory alone. Treat it as the whole secret of the workspace and keep it out of version control. Without `dataDir`, nothing changes: a temporary directory, a random port, and everything removed by `close()`.

To develop an app behind forward auth, pass a `cookieDomain`:

```ts
const issuer = await startDisposableIssuer({
  resources: [{ identifier: "http://app.notes.localhost:8080/", name: "Notes", scopes: [] }],
  client: { name: "Notes console", redirect: "http://localhost:5173/callback", resources: [] },
  cookieDomain: "notes.localhost",
});

issuer.url; // http://auth.notes.localhost:<port>
```

The issuer then serves `/forward-auth?resource=<identifier>`, `/forward-auth/continue` and `/forward-auth/logout`, and shares its forward cookie with every host under the domain, so serve the app on one, such as `app.notes.localhost`. Browsers and Node resolve `.localhost` names to loopback without a hosts-file entry. A signed-in owner's check answers `204` with an `Authorization` header to copy upstream; without a session, a page navigation (`Sec-Fetch-Mode: navigate`) is redirected through sign-in and any other request is `401`. Without `cookieDomain` the issuer is `http://127.0.0.1:<port>` and these routes are not served.

## The edge

`@gjermundgaraba/clankerauth-dev/edge` is the deployment edge for local development: the `forward_auth` check, and for upgrades a reverse proxy. Do not write one again.

```ts
import { forwardAuth, reserveLoopbackPort } from "@gjermundgaraba/clankerauth-dev/edge";

export default defineConfig({
  plugins: [
    forwardAuth({
      issuer: "http://auth.notes.localhost:5174",
      appOrigin: "http://app.notes.localhost:5173",
      resource: "http://app.notes.localhost:5173/",
      sockets: { backend: "http://127.0.0.1:8080", paths: ["/eventlog"] },
      onError: (error) => console.error("[forward-auth]", error.message),
    }),
  ],
});
```

Nothing in this package imports Vite, at run time or in its types: the plugin is the plain object Vite accepts. On a plain Node server, `attach(server, options)` installs the same two halves and returns the request middleware; `check(options)` and `middleware(options)` are available on their own.

- The check uses `node:http`, never `fetch`: `fetch` owns `Sec-Fetch-Mode`, and that header is what tells the issuer whether a request may be redirected through sign-in. The browser's own header is relayed, along with its cookie, plus `x-forwarded-proto`, `-host` and `-uri`.
- It has a timeout (5 s by default) and **rejects** rather than deciding when the issuer is unreachable, too slow, or answers `204` with no `Authorization` to forward. `middleware` turns a rejection into a 502 and passes the error to `onError`; an empty credential is never forwarded upstream.
- A refusal is relayed as the issuer wrote it: its status, its `Location`, its body and its content type. A script that is not signed in reads `{"error":"unauthenticated"}` rather than an empty 401.
- `publicPaths` defaults to `/mcp`, `/.well-known` and `/healthz`, and a request that already carries an `Authorization` header is never checked: agents onboard themselves and probes run.
- `upgrade` only takes the paths in `sockets.paths`, so a development server keeps its own hot-reload socket; it returns `false` for everything else, which on a plain Node server means another listener must answer them. Omit `sockets` and it takes none. A checked upgrade is proxied to `sockets.backend`; a half closing normally ends the other half, and only an error destroys. A client that gives up while the issuer is deciding is not proxied at all. A socket error is reported through `onError` and never crashes the server.
- `reserveLoopbackPort()` claims a free port before anything that must know its own origin up front.

The edge's types import `node:http` types, so a TypeScript consumer needs `@types/node`.

Two optional test hooks help exercise integrations:

- `cimdTransport(input, init)` replaces outbound Client ID Metadata Document retrieval and returns a `Response` or `Promise<Response>`. Its arguments match `fetch`. Use it to serve fixture metadata for HTTPS client IDs without an external server. When omitted, the issuer uses its secure metadata transport.
- `onRequest({ method, url })` observes actual incoming HTTP requests at the issuer listener, such as discovery, JWKS, dynamic client registration, and token requests. Provisioning is in-process, so the observer sees only the test's own traffic. `url` is a `URL`; headers and bodies are never passed. The callback runs synchronously before handling each request. A thrown error makes that request fail with HTTP 500, so keep observers nonthrowing.

## A fake issuer for tests

`@gjermundgaraba/clankerauth-dev/testing` is the issuer an application test usually wants: the two endpoints a resource server actually calls, and nothing else. It signs with a real EdDSA key and publishes it as JWKS, so every token still travels the resource server's own verifier — signature, issuer, audience, type, claims, scopes — without starting the whole issuer.

```ts
import { startFakeIssuer } from "@gjermundgaraba/clankerauth-dev/testing";

const auth = await startFakeIssuer({
  resource: "http://127.0.0.1:8080/",
  scopes: ["notes:read", "notes:write"],
});

auth.issuer; // configure the resource server with this
const token = await auth.sign(); // every claim is overridable: auth.sign({ exp, aud, scope })
const key = auth.apiKey(["notes:read"]); // and auth.apiKey(scopes, someOtherResource)
auth.revoke(key); // the next verification is 401, online, as the real issuer behaves
auth.fail(503); // both endpoints answer this instead; auth.fail() restores them
auth.verifications(); // how many API-key verifications were served
await auth.close();
```

Use it for what a real issuer makes slow or awkward: a token that must expire in two seconds, a key granted on someone else's resource, an outage. Use `startDisposableIssuer` when the protocol itself is what the test is about — sign-in, consent, forward auth, dynamic registration.

MIT licensed. The bundled third-party licenses are listed in `dist/THIRD_PARTY_NOTICES.txt`.
