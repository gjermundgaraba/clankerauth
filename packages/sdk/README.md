# @gjermundgaraba/clankerauth-sdk

Effect-native [Clanker Auth](https://github.com/gjermundgaraba/clankerauth) verification. Verifies JWT access tokens and API keys, including the tokens a reverse proxy obtains through the issuer's forward auth for browser sessions. Optional **effect-actions** integration provides request-scoped identity, OAuth discovery, scope enforcement and a `session` contract a browser page can import on its own.

## Install

```sh
vp add @gjermundgaraba/clankerauth-sdk
```

Install Effect in the application:

```sh
vp add effect@4.0.0-rc.116
```

## Entry points

| Import                             | Needs effect-actions | Browser safe | What it holds                                     |
| ---------------------------------- | -------------------- | ------------ | ------------------------------------------------- |
| `…/clankerauth-sdk`                | no                   | no           | `Verifier`, `RequestPolicy`                       |
| `…/clankerauth-sdk/errors`         | no                   | **yes**      | the error schemas and `authenticationErrors`      |
| `…/clankerauth-sdk/session`        | yes                  | **yes**      | the `session` contract, `Principal`, `signOutUrl` |
| `…/clankerauth-sdk/effect-actions` | yes                  | no           | `Resource`, `CurrentPrincipal`                    |

The package is free of side effects, so a bundler drops what a page does not use. Errors are **not** re-exported from the root: a shared contract imports them from `/errors`, and nothing about that import pulls token verification into a browser bundle.

## Verify tokens directly

Core consumers do not need effect-actions or `skipLibCheck`.

```ts
import { Effect } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";

const makeVerifier = Verifier.make({
  issuer: "https://auth.internal/api/auth",
  resource: "https://notes.internal/",
  requiredScopes: ["notes:read"],
}).pipe(Effect.provide(FetchHttpClient.layer));
// Acquire once, then use verifier.verify(authorization) or verifier.verifyToken(token).
```

## One resource per application

Register **one** resource in the Clanker Auth dashboard, identified by the application's public origin root, written with its trailing slash: `https://notes.internal/`. That one resource covers `/api`, `/mcp` and any socket, with one RFC 9728 document at `/.well-known/oauth-protected-resource` and one `forward_auth` block in the proxy.

`Resource.make` takes the public URL and derives that identifier itself, so the application never writes it twice and never writes a form an MCP client would rewrite. Any path on the URL is discarded. The official client's own `checkResourceAllowed` accepts an origin-root resource for an endpoint beneath it.

Acquire the resource once at application construction, never per request.

```ts
import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { McpProtocol } from "effect/unstable/ai";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import { authenticationErrors } from "@gjermundgaraba/clankerauth-sdk/errors";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";

// Http and app are your effect-actions HTTP binding and implemented group.
const routes = Layer.unwrap(
  Effect.gen(function* () {
    const notes = yield* Resource.make({
      issuer: "https://auth.internal/api/auth",
      publicUrl: new URL("https://notes.internal"),
      scopes: { read: "notes:read", write: "notes:write" },
    });

    return Layer.mergeAll(
      notes.discovery.layer,
      Http.layer([app, notes.session], { before: notes.authorize }).pipe(
        Layer.provide(Resource.middleware(notes).layer),
      ),
      ActionMcp.layerHttp([app], {
        name: "notes",
        version: "1.0.0",
        path: "/mcp",
        protocols: [McpProtocol.v2026_07_28],
        errors: authenticationErrors,
        before: notes.authorize,
      }).pipe(Layer.provide(Resource.middleware(notes).layer)),
    );
  }),
).pipe(Layer.provide(FetchHttpClient.layer));
```

Serve this layer with Effect's `HttpRouter` and your Node server layer. If using `@effect/platform-node`, install the matching `@effect/platform-node@4.0.0-rc.116` package. Discovery is public; do not wrap it in authentication. Discovery cache policy belongs to the host. Every authentication response carries `Cache-Control: no-store`.

The supplied `HttpClient` must not retry credential exchanges or follow redirects. The SDK overrides only FetchHttpClient's redirect policy to reject redirects, preserves other caller-provided fetch defaults, and never installs retry middleware.

## Scope enforcement

An application names its scopes once and writes no authorization code. Each action declares what it does to the resource, and `resource.authorize` is the surface's pre-handler hook: it runs after the input is decoded and before every handler on every surface — HTTP, MCP, Toolkit, CLI — so no handler can forget it.

```ts
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionGroup from "@gjermundgaraba/effect-actions/ActionGroup";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { authenticationErrors } from "@gjermundgaraba/clankerauth-sdk/errors";
import { Session } from "@gjermundgaraba/clankerauth-sdk/session";

const Notes = ActionGroup.make(
  { name: "notes" },
  Action.make("list", { description: "List notes", access: "read", success: Notes }),
  Action.make("write", { description: "Write a note", access: "write", success: Note }),
);

// Declared on the surface, because the surface is what renders them — including the
// hook's own refusals, which is why the group no longer lists `InsufficientScope`.
const Http = ActionHttp.make({ apiPath: "/api", errors: authenticationErrors }, Notes, Session);

// And bound once per surface, so no handler and no group can forget it.
const routes = Http.layer([Notes.implement(handlers), notes.session], { before: notes.authorize });
```

`scopes.read` is required at verification, so a read needs nothing further. `scopes.write` is what an `access: "write"` action additionally needs; leave it out and every action passes, which is how a single-scope application is expressed. `InsufficientScope` is a 403 naming **only** the missing scope, so a refusal never enumerates the resource's permissions.

A forward-auth browser token carries **every** scope the resource defines, because the issuer mints it for the signed-in owner and not for a program. The write scope therefore gates agents and API keys, not the owner at a keyboard: give a read-only agent or key only `scopes.read` and the same rule refuses its writes.

An action reads identity from `CurrentPrincipal`, which contains `subject`, `scopes`, `actor` — either `{ kind: "client", clientId }` or `{ kind: "key", keyId }` — and `expiresAt`: an access token's verified `exp` in epoch milliseconds, so a host bounding a connection to its credential never decodes the token again. It is `undefined` for an API key, which carries no token lifetime and is re-verified on every request; choose your own bound for those.

A hook refusal is a plain declared error: effect-actions encodes it with the schema's status and adds no headers of its own; `Cache-Control: no-store` comes from `Resource.middleware`, which wraps every route it authenticates. Challenge headers come from admission — `Resource.middleware` and `admit` — which is what a client onboarding through RFC 9728 reads. No current client reads the header on a scope refusal, because an MCP denial is a tool error.

Middleware authenticates the request and the hook authorizes it; neither filters MCP tool discovery.

## Outside the router

A socket, a Node `upgrade` handler or a per-request endpoint verifies the same credential against the same resource, and renders the same refusal, with `admit`. The access level is required, so the call says what the credential is for:

```ts
const admission = await Effect.runPromise(notes.admit(request.headers.authorization, "write"));

if (!admission.ok) {
  const { status, headers, body } = admission.refusal;
  response.writeHead(status, headers).end(body);
  return;
}

connect(admission.principal);
```

The refusal carries each error's own status (401/403/429/503), the RFC 6750 challenge including the no-credential case, `Cache-Control: no-store`, and the error's JSON encoding. `Resource.middleware` is built on the same function at `"read"`, so a router and a socket can never answer differently.

The resource also exposes `verifier.verify(authorization)` and `verifier.verifyToken(token)` as Effects for callers that render their own responses.

## Request policy

Forward auth makes a browser's credential ambient: the proxy attaches an `Authorization` header to whatever the browser sends, including a cross-site navigation. So an application behind it checks where a request came from before anything reads the credential.

```ts
import { RequestPolicy } from "@gjermundgaraba/clankerauth-sdk";

const policy = RequestPolicy.make({
  publicUrl: new URL("https://notes.internal"),
  allowedOrigins: ["wtf://app"], // a desktop shell's private renderer scheme
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

Both checks are raw string comparisons on the headers as sent. Nothing is parsed, so nothing throws and no normalization widens what is accepted: `notes.internal` and `notes.internal:443` are different hosts here, as they are to a browser's cookie. A request with no `Host` is refused. An absent `Origin` is allowed; a present one must match exactly. `/healthz` is the one path answered without either check, because a container probe reaches the app on its bind address and carries neither header; it is fixed, not configurable. This is not authentication, and it does not set body limits or security headers — those stay the application's.

## Browser applications

A browser page holds no credential of its own: put it behind a reverse proxy with the issuer's forward auth, described in the Clanker Auth README, and the proxy adds the `Authorization` header this package verifies. What the page does need is who it is signed in as, and a way out:

```ts
import { Principal, Session, signOutUrl } from "@gjermundgaraba/clankerauth-sdk/session";

// `Session` is the contract; the server answers it with `resource.session`.
const principal: Principal = await api.session.whoami({ payload: {} });
link.href = signOutUrl(principal.issuer, `${location.origin}/`);
```

`Principal` is `{ subject, issuer, scopes }`. `signOutUrl` points at the issuer's `/forward-auth/logout?rd=…`, which ends the issuer session and every app's forward cookie; it is a plain link. On the server, `resource.session` is the same group already implemented from the verified credential — pass it to the HTTP binding beside your own application, and delete the hand-written `whoami`.

## Errors and observability

Schema-tagged errors, all from `@gjermundgaraba/clankerauth-sdk/errors`: `Unauthorized` (401), `InsufficientScope` (403), `RateLimited` (429) and `ProviderUnavailable` (503), collected as `authenticationErrors`. Invalid construction fails with `ConfigurationError`.

There is one 403. A credential that is valid but lacks a scope is `InsufficientScope`; a credential that is not this resource's at all — the wrong audience, or an API key with no grant here, which the issuer answers `403` for — is `Unauthorized`, because from the resource's side those are the same thing.

JWTs are checked against issuer, audience, EdDSA signature, token type, required claims, expiry and scopes. Sender-constrained tokens are rejected. One JWKS read answers every verification for a minute, so a key the issuer starts or stops publishing takes effect within that minute; a `kid` the current document does not publish is `Unauthorized` and never triggers a read, so unauthenticated requests cannot become provider traffic. A failed read, or one whose caller gave up, answers `ProviderUnavailable` (503) for five seconds before the next attempt. API keys are checked online on **every request**, so revocation is effective immediately. A resource that accepts only OAuth access tokens sets `apiKeys: false`; key-shaped bearers then fail as `Unauthorized` without contacting the issuer. Admission through a `Resource` has a five-second deadline; the raw `Verifier` has none, so an in-process caller can await a provider call it cannot cancel.

The bundled issuer does not configure automatic signing-key rotation. Immediate-use rotation is supported, but tokens signed by a new key are rejected until the next JWKS read, up to a minute. Publish-before-use avoids that window; it is not mandatory.

The SDK Resource adapter owns authentication error encoding and challenge headers; effect-actions supplies request-scoped identity, and its authentication middleware marks every response it answers or wraps `Cache-Control: no-store`; other cache policy is the host's. Defects and interruption are not relabeled as authentication rejection. Named effects supply tracing boundaries; application logging/tracing layers remain caller-owned. No `onFailure` callbacks or hidden runtime.

Operational failures retain their underlying `cause` for application-side Effect error handling. `ProviderUnavailable` and `Unauthorized` keep this diagnostic field outside their public schemas; effect-actions serializes only those schemas. Causes may contain sensitive transport or provider details: inspect selectively, never serialize them into responses or log them indiscriminately.

MIT licensed.
