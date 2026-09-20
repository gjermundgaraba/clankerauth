# @gjermundgaraba/clankerauth-sdk

Effect-native [Clanker Auth](https://github.com/gjermundgaraba/clankerauth) verification and browser sessions. Verifies JWT access tokens and API keys and runs browser login with encrypted server-held credentials. Optional **effect-actions** integration provides request-scoped identity and OAuth discovery.

## Install

Published to GitHub Packages. Configure the scope and keep the credential in your user-level `~/.npmrc`:

```sh
echo '@gjermundgaraba:registry=https://npm.pkg.github.com' >> .npmrc
echo '//npm.pkg.github.com/:_authToken=${GH_TOKEN}' >> ~/.npmrc
vp add @gjermundgaraba/clankerauth-sdk
```

Install Effect in the application:

```sh
vp add effect@4.0.0-rc.116
```

## Verify tokens directly

Core consumers do not need effect-actions or `skipLibCheck`.

```ts
import { Effect } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { McpProtocol } from "effect/unstable/ai";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";

const makeVerifier = Verifier.make({
  issuer: "https://auth.internal/api/auth",
  resource: "https://notes.internal/api",
  requiredScopes: ["notes:read"],
}).pipe(Effect.provide(FetchHttpClient.layer));
// Acquire once, then use verifier.verify(authorization) or verifier.verifyToken(token).
```

## Protect effect-actions routes

Install the optional peer dependency and import the integration subpath:

```sh
vp add @gjermundgaraba/effect-actions@0.1.0-rc.2
```

Core and integration declarations both type-check without `skipLibCheck`.

Register a resource in the Clanker Auth dashboard. Its identifier is the exact audience URL, not just an origin. Acquire one resource capability per protected audience at application construction, not per request.

```ts
import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { McpProtocol } from "effect/unstable/ai";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";

// Http and app are your effect-actions HTTP binding and implemented group.
const routes = Layer.unwrap(
  Effect.gen(function* () {
    const api = yield* Resource.make({
      issuer: "https://auth.internal/api/auth",
      resource: "https://notes.internal/api",
      scopes: ["notes:read", "notes:write"],
      requiredScopes: ["notes:read"],
    });
    const mcp = yield* Resource.make({
      issuer: "https://auth.internal/api/auth",
      resource: "https://notes.internal/mcp",
      scopes: ["notes:read", "notes:write"],
      requiredScopes: ["notes:read"],
    });
    return Layer.mergeAll(
      api.discovery.layer,
      mcp.discovery.layer,
      Http.layer(app).pipe(Layer.provide(Resource.middleware(api).layer)),
      ActionMcp.layerHttp(
        { name: "notes", version: "1.0.0", path: "/mcp", protocols: [McpProtocol.v2026_07_28] },
        app,
      ).pipe(Layer.provide(Resource.middleware(mcp).layer)),
    );
  }),
).pipe(Layer.provide(FetchHttpClient.layer));
```

Serve this layer with Effect's `HttpRouter` and your Node server layer. If using `@effect/platform-node`, install the matching `@effect/platform-node@4.0.0-rc.116` package. Discovery is public; do not wrap it in authentication. Discovery cache policy belongs to the host. Authentication responses use `Cache-Control: no-store`.

The supplied `HttpClient` must not retry credential exchanges or follow redirects. The SDK overrides only FetchHttpClient's redirect policy to reject redirects, preserves other caller-provided fetch defaults, and never installs retry middleware.

An action reads identity from `CurrentPrincipal` and enforces its own permissions:

```ts
import { Effect } from "effect";
import { Forbidden } from "@gjermundgaraba/clankerauth-sdk";
import { CurrentPrincipal } from "@gjermundgaraba/clankerauth-sdk/effect-actions";

const write = Effect.gen(function* () {
  const principal = yield* CurrentPrincipal;
  if (!principal.scopes.includes("notes:write")) {
    return yield* new Forbidden({ message: "Write permission required" });
  }
  return principal.subject;
});
```

Declare `Forbidden` in that action/group's error schemas. Middleware authenticates the request; it does not infer per-action policy or filter MCP tool discovery.

A principal contains `subject`, `scopes`, and `actor`: either `{ kind: "client", clientId }` or `{ kind: "key", keyId }`. The resource also exposes `verifier.verify(authorization)` and `verifier.verifyToken(token)` as Effects.

JWTs are checked against issuer, audience, EdDSA signature, token type, required claims, expiry and scopes. Sender-constrained tokens are rejected. JWKS lookups are cached for ten minutes. Unknown keys trigger one refresh and resolution retry, with a thirty-second cooldown to bound provider traffic. Failed miss-triggered refreshes also cool down and return 503; still-valid cached keys remain usable. Initial lookup failures are not retained. Removed keys can remain trusted until cache expiry. API keys are checked online on **every request**, so revocation is effective immediately. A resource that accepts only OAuth access tokens sets `apiKeys: false`; key-shaped bearers then fail as `Unauthorized` without contacting the issuer. Verification has a five-second deadline.

The bundled issuer does not configure automatic signing-key rotation. Immediate-use rotation is supported, but tokens signed by a new key can be rejected during the thirty-second cooldown after a successful lookup. Publish-before-use avoids that short window; it is not mandatory.

## Browser sessions

Register a confidential client with the exact `callbackUrl` supplied to the session. It must be an absolute HTTP(S) URL without credentials or a fragment; query parameters are allowed. The session derives its browser origin and secure-cookie policy from this URL.

Provide a `SessionStore` layer implementing Effect operations:

- `get(id)` → `{ payload, expires } | undefined`
- `put(id, payload, expires)`
- `delete(id)`
- `sweep(now)`: remove rows expiring at or before `now`

Map expected database failures to `StoreError({ operation, cause })` at your persistence adapter. Do not put SQL, secrets, credentials or provider payloads in public errors. The store owns persistence, not encryption or session policy. **Run one process per store and acquire one shared browser-session capability per cookie/store configuration.**

```ts
import { Effect, Layer, Redacted } from "effect";
import { BrowserSession } from "@gjermundgaraba/clankerauth-sdk";
import { BrowserActions, Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";

// Inside application construction, with HttpClient and SessionStore provided:
const browser =
  yield *
  BrowserSession.make({
    issuer: "https://auth.internal/api/auth",
    resource: "https://notes.internal/api",
    callbackUrl: "https://notes.internal/workspace/auth/callback",
    clientId,
    clientSecret: Redacted.make(clientSecret),
    secret: Redacted.make(sessionSecret), // at least 32 characters; retain across restarts
    scopes: ["notes:read", "notes:write"],
    cookie: { name: "notes" },
    verifyToken: api.verifier.verifyToken,
  });

const browserRoutes = Layer.mergeAll(
  BrowserActions.layer(browser),
  Http.layer(app).pipe(Layer.provide(Resource.middleware(api, { browser }).layer)),
);
```

This example's construction fragment belongs inside `Effect.gen`. Supply configuration and secrets at your composition root; the SDK does not read environment variables or start its own runtime.

`BrowserActions.layer` registers:

- `POST /auth/browser/login`: accepts `{ returnTo: "/path" }`, returns `{ url }`.
- `GET <callback pathname>`: consumes the one-time transaction and redirects (`/workspace/auth/callback` above).
- `POST /auth/browser/session`: returns the subject, scopes and issuer, or `Unauthorized`.
- `POST /auth/browser/logout`: ends the local session and attempts provider revocation.

Login, session and logout are effect-actions, with JSON bodies (`{}` for session and logout). Browser clients import the pure `Http` contract from `@gjermundgaraba/clankerauth-sdk/browser-api`. Only the OAuth callback is an ordinary HTTP endpoint. The callback uses the exact configured URL; action routes live under `/auth/browser`. Callback failures redirect to the origin root with an `auth_error` query parameter; a root-mounted callback returns the sanitized HTTP error to avoid a redirect loop. Login destinations must be same-origin paths other than the callback pathname. The host sets request-body limits, for example `HttpIncomingMessage.MaxBodySize` on Effect's Node server (Clanker Auth's own adapter uses 64 KiB). Responses are non-cacheable and use `Referrer-Policy: no-referrer`.

Tokens always remain in the server-side session store, never in browser JavaScript.

Pass `browser` only for HTTP routes the application's own pages call. A request with an Authorization header is always verified as a bearer token; without one, the session cookie authenticates it and Origin is checked on unsafe methods. **Never pass `browser` for MCP.**

The session capability does not accept incoming HTTP requests: `login(returnTo)`, `callback(url, transactionCookie)`, `session(sessionCookie)`, `accessToken(sessionCookie)`, and `logout(sessionCookie)` are Effects. HTTP handlers own cookie extraction and presentation.

Cookies are HttpOnly, SameSite=Lax and Secure on HTTPS. Login uses S256 PKCE, state, nonce, exact issuer validation and signed ID-token checks. Stored payloads remain AES-256-GCM sealed under the configured secret with hashed cookie identifiers.

Refreshes and logout serialize per session. A durable no-replay marker is written before refresh; interruptions, ambiguous outcomes and restarts cannot reuse that refresh token. Discovery failure before the marker remains retryable. Operational refresh failures return 503 and invalidate the session; subsequent access requires login. Local logout remains authoritative if provider revocation fails, with a sanitized Effect warning.

## Errors and observability

Schema-tagged errors: `Unauthorized` (401), `Forbidden` (403), `RateLimited` (429), `ProviderUnavailable` and `StoreError` (503). Browser input errors use `InvalidRequest` (400). Invalid construction fails with `ConfigurationError`.

The SDK Resource adapter owns authentication error encoding and challenge headers; effect-actions supplies request-scoped identity and the no-store response policy. Browser actions use their declared error schemas; the callback handles redirects. Defects and interruption are not relabeled as authentication rejection. Named effects supply tracing boundaries; application logging/tracing layers remain caller-owned. No `onFailure` callbacks or hidden runtime.

Operational failures retain their underlying `cause` for application-side Effect error handling. `ProviderUnavailable`, `StoreError`, and `Unauthorized` keep this diagnostic field outside their public schemas; BrowserActions and effect-actions serialize only those schemas. Causes may contain sensitive transport or provider details: inspect selectively, never serialize them into responses or log them indiscriminately.

MIT licensed.
