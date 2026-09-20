# @gjermundgaraba/clankerauth-sdk

Effect-native [Clanker Auth](https://github.com/gjermundgaraba/clankerauth) verification. Verifies JWT access tokens and API keys, including the tokens a reverse proxy obtains through the issuer's forward auth for browser sessions. Optional **effect-actions** integration provides request-scoped identity and OAuth discovery.

## Install

```sh
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
vp add @gjermundgaraba/effect-actions@0.2.0
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

## Browser applications

Browser apps do not use this package. Put them behind a reverse proxy with the issuer's forward auth, described in the Clanker Auth README; the proxy adds an `Authorization` header the same verifier above accepts.

## Errors and observability

Schema-tagged errors: `Unauthorized` (401), `Forbidden` (403), `RateLimited` (429) and `ProviderUnavailable` (503). Invalid construction fails with `ConfigurationError`.

The SDK Resource adapter owns authentication error encoding and challenge headers; effect-actions supplies request-scoped identity and the no-store response policy. Defects and interruption are not relabeled as authentication rejection. Named effects supply tracing boundaries; application logging/tracing layers remain caller-owned. No `onFailure` callbacks or hidden runtime.

Operational failures retain their underlying `cause` for application-side Effect error handling. `ProviderUnavailable` and `Unauthorized` keep this diagnostic field outside their public schemas; effect-actions serializes only those schemas. Causes may contain sensitive transport or provider details: inspect selectively, never serialize them into responses or log them indiscriminately.

MIT licensed.
