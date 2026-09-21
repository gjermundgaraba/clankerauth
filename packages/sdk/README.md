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
vp add @gjermundgaraba/effect-actions@0.3.0
```

Core and integration declarations both type-check without `skipLibCheck`.

## One resource per application

Register **one** resource in the Clanker Auth dashboard, identified by the application's public origin root, written with its trailing slash: `https://notes.internal/`. That one resource covers `/api`, `/mcp` and any socket, with one RFC 9728 document at `/.well-known/oauth-protected-resource` and one `forward_auth` block in the proxy.

The identifier must already be canonical: `new URL(id).href === id`. An MCP client sends `new URL(metadata.resource).href` and the access token's audience is that string, so `https://notes.internal` (no slash) would be rewritten by the client and no longer match the issuer's registered resource. `Resource.make` refuses it with `ConfigurationError` rather than let that fail later. The official client's own `checkResourceAllowed` accepts an origin-root resource for an endpoint beneath it.

Acquire the resource once at application construction, never per request.

```ts
import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { McpProtocol } from "effect/unstable/ai";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";

// Http and app are your effect-actions HTTP binding and implemented group.
const routes = Layer.unwrap(
  Effect.gen(function* () {
    const notes = yield* Resource.make({
      issuer: "https://auth.internal/api/auth",
      resource: "https://notes.internal/",
      scopes: ["notes:read", "notes:write"],
      requiredScopes: ["notes:read"],
      writeScope: "notes:write",
    });

    return Layer.mergeAll(
      notes.discovery.layer,
      Http.layer(app).pipe(Layer.provide(Resource.middleware(notes).layer)),
      ActionMcp.layerHttp(
        { name: "notes", version: "1.0.0", path: "/mcp", protocols: [McpProtocol.v2026_07_28] },
        app,
      ).pipe(Layer.provide(Resource.middleware(notes).layer)),
    );
  }),
).pipe(Layer.provide(FetchHttpClient.layer));
```

Serve this layer with Effect's `HttpRouter` and your Node server layer. If using `@effect/platform-node`, install the matching `@effect/platform-node@4.0.0-rc.116` package. Discovery is public; do not wrap it in authentication. Discovery cache policy belongs to the host. Authentication responses use `Cache-Control: no-store`.

The supplied `HttpClient` must not retry credential exchanges or follow redirects. The SDK overrides only FetchHttpClient's redirect policy to reject redirects, preserves other caller-provided fetch defaults, and never installs retry middleware.

## Scope enforcement

An application names two scopes and writes no authorization code. Each action declares what it does to the resource, and the resource's `authorize` is the group's pre-handler hook: it runs before every handler on every surface — HTTP, MCP, Toolkit, CLI — so no handler can forget it.

```ts
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionGroup from "@gjermundgaraba/effect-actions/ActionGroup";
import { InsufficientScope } from "@gjermundgaraba/clankerauth-sdk";

const Notes = ActionGroup.make(
  { name: "notes", errors: [InsufficientScope] },
  Action.make("list", { description: "List notes", access: "read", success: Notes }),
  Action.make("write", { description: "Write a note", access: "write", success: Note }),
);

// `notes` is the acquired Resource above, configured with `writeScope`.
const app = Notes.implement(handlers, { before: notes.authorize });
```

A read needs nothing beyond what verification already required. A write needs the configured `writeScope`; without one, `authorize` passes every action, so a single-scope resource is expressed by leaving it out. `InsufficientScope` is a 403 naming **only** the missing scope, so a refusal never enumerates the resource's permissions. Declare it on the group.

An action still reads identity from `CurrentPrincipal`, which contains `subject`, `scopes`, `actor` — either `{ kind: "client", clientId }` or `{ kind: "key", keyId }` — and `expiresAt`: an access token's verified `exp` in epoch milliseconds, so a host bounding a connection to its credential never decodes the token again. It is `undefined` for an API key, which carries no token lifetime and is re-verified on every request; choose your own bound for those.

Middleware authenticates the request and the hook authorizes it; neither filters MCP tool discovery.

## Outside the router

A socket, a Node `upgrade` handler or a per-request endpoint verifies the same credential against the same resource, and renders the same refusal, with `admit`:

```ts
const admission = await Effect.runPromise(notes.admit(request.headers.authorization, "write"));

if (!admission.ok) {
  const { status, headers, body } = admission.refusal;
  response.writeHead(status, headers).end(body);
  return;
}

connect(admission.principal);
```

The refusal carries each error's own status (401/403/429/503), the RFC 6750 challenge including the no-credential case, `Cache-Control: no-store`, and the error's JSON encoding. Passing `"write"` demands the write scope before the socket is established. `Resource.middleware` is built on the same function, so a router and a socket can never answer differently.

The resource also exposes `verifier.verify(authorization)` and `verifier.verifyToken(token)` as Effects for callers that render their own responses.

## Request policy

Forward auth makes a browser's credential ambient: the proxy attaches an `Authorization` header to whatever the browser sends, including a cross-site navigation. So an application behind it checks where a request came from before anything reads the credential.

```ts
import { RequestPolicy } from "@gjermundgaraba/clankerauth-sdk";

const policy = RequestPolicy.make({
  publicUrl: new URL("https://notes.internal"),
  allowedOrigins: ["wtf://app"], // a desktop shell's private renderer scheme
  exemptPaths: ["/healthz"], // a container probe carries neither header
});

const routes = protectedRoutes.pipe(Layer.provide(policy.middleware.layer));

// The same decision from a Node upgrade handler, with no services:
if (
  !policy.allows({
    target: request.url,
    host: request.headers.host,
    origin: request.headers.origin,
  })
) {
  socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
}
```

Both checks are raw string comparisons on the headers as sent. Nothing is parsed, so nothing throws and no normalization widens what is accepted: `notes.internal` and `notes.internal:443` are different hosts here, as they are to a browser's cookie. A request with no `Host` is refused unless its path is exempt. An absent `Origin` is allowed; a present one must match exactly. This is not authentication, and it does not set body limits or security headers — those stay the application's.

JWTs are checked against issuer, audience, EdDSA signature, token type, required claims, expiry and scopes. Sender-constrained tokens are rejected. JWKS lookups are cached for ten minutes. Unknown keys trigger one refresh and resolution retry, with a thirty-second cooldown to bound provider traffic. Failed miss-triggered refreshes also cool down and return 503; still-valid cached keys remain usable. Initial lookup failures are not retained. Removed keys can remain trusted until cache expiry. API keys are checked online on **every request**, so revocation is effective immediately. A resource that accepts only OAuth access tokens sets `apiKeys: false`; key-shaped bearers then fail as `Unauthorized` without contacting the issuer. Verification has a five-second deadline.

The bundled issuer does not configure automatic signing-key rotation. Immediate-use rotation is supported, but tokens signed by a new key can be rejected during the thirty-second cooldown after a successful lookup. Publish-before-use avoids that short window; it is not mandatory.

## Browser applications

Browser apps do not use this package. Put them behind a reverse proxy with the issuer's forward auth, described in the Clanker Auth README; the proxy adds an `Authorization` header the same verifier above accepts.

## Errors and observability

Schema-tagged errors: `Unauthorized` (401), `Forbidden` (403), `InsufficientScope` (403), `RateLimited` (429) and `ProviderUnavailable` (503). Invalid construction fails with `ConfigurationError`.

The SDK Resource adapter owns authentication error encoding and challenge headers; effect-actions supplies request-scoped identity and the no-store response policy. Defects and interruption are not relabeled as authentication rejection. Named effects supply tracing boundaries; application logging/tracing layers remain caller-owned. No `onFailure` callbacks or hidden runtime.

Operational failures retain their underlying `cause` for application-side Effect error handling. `ProviderUnavailable` and `Unauthorized` keep this diagnostic field outside their public schemas; effect-actions serializes only those schemas. Causes may contain sensitive transport or provider details: inspect selectively, never serialize them into responses or log them indiscriminately.

MIT licensed.
