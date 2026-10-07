# @gjermundgaraba/clankerauth-sdk

Effect-native [clankerauth](https://github.com/gjermundgaraba/clankerauth) verification. Verifies JWT access tokens and API keys, both offline, including the tokens a reverse proxy obtains through the issuer's forward auth for browser sessions. Optional **effect-actions** integration provides the verifier behind an authentication descriptor, OAuth discovery, scope enforcement and the `Whoami` contract, which a browser page imports on its own from `/session`.

## Install

```sh
vp add @gjermundgaraba/clankerauth-sdk
```

Effect is a peer: the application installs Effect 4, and the SDK shares that copy.

```sh
vp add effect
```

The `/session` and `/effect-actions` entry points also need effect-actions, an optional peer. Install this range: the SDK's declarations are built against it, and under `skipLibCheck` they silently degrade to `any` with another.

```sh
vp add @gjermundgaraba/effect-actions@^0.10.0
```

## Entry points

| Import                             | Needs effect-actions | Browser safe | What it holds                                                                         |
| ---------------------------------- | -------------------- | ------------ | ------------------------------------------------------------------------------------- |
| `…/clankerauth-sdk`                | no                   | no           | `Verifier`, `RequestPolicy`                                                           |
| `…/clankerauth-sdk/errors`         | no                   | **yes**      | the verifier's errors; `ProviderUnavailable` is the one a descriptor declares         |
| `…/clankerauth-sdk/session`        | yes                  | **yes**      | `CurrentPrincipal` and its `Caller`, the `Whoami` contract, `Principal`, `signOutUrl` |
| `…/clankerauth-sdk/effect-actions` | yes                  | no           | `Resource`                                                                            |
| `…/clankerauth-sdk/key-list`       | no                   | no           | the key list format, for issuers and fakes                                            |
| `…/clankerauth-sdk/testing`        | no                   | no           | `startFakeIssuer`, for tests (Node only)                                              |

The package is free of side effects, so a bundler drops what a page does not use. Errors are **not** re-exported from the root: a shared contract imports them from `/errors`, and nothing about that import pulls token verification into a browser bundle.

## Verify tokens directly

Core consumers do not need effect-actions or `skipLibCheck`.

```ts
import { Effect } from "effect";
import { FetchHttpClient } from "effect/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";

const makeVerifier = Verifier.make({
  issuer: "https://clankerauth.internal/api/auth",
  resource: "https://notes.internal/",
  requiredScopes: ["notes:read"],
}).pipe(Effect.provide(FetchHttpClient.layer));
// Acquire once, then use verifier.verifyToken(token).
```

## One resource per application

Register **one** resource in the clankerauth dashboard, identified by the application's public origin root, written with its trailing slash: `https://notes.internal/`. That one resource covers `/api`, `/mcp` and any socket, with one RFC 9728 document at `/.well-known/oauth-protected-resource` and one `forward_auth` block in the proxy.

A declared resource's `layer` takes the public URL and derives that identifier itself, so the application never writes it twice and never writes a form an MCP client would rewrite. Any path on the URL is discarded. The official client's own `checkResourceAllowed` accepts an origin-root resource for an endpoint beneath it.

Contracts state who may call them, `caller: CurrentPrincipal`, and a binding names how a caller proves it: an effect-actions authentication descriptor, declared once beside the contracts, where a browser client imports it too. The descriptor also declares what its verifier fails with besides a refusal: `ProviderUnavailable`, the issuer being unreachable.

```ts
// contracts.ts: browser-safe.
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { ProviderUnavailable } from "@gjermundgaraba/clankerauth-sdk/errors";
import { CurrentPrincipal, Whoami } from "@gjermundgaraba/clankerauth-sdk/session";

// A bearer token proving a `CurrentPrincipal`. Its name is unique per process. Refusals are
// effect-actions' built-in `Unauthenticated` and `Forbidden`, declared on every endpoint; the
// descriptor declares the one answer that is the SDK's own, the 503, which every protected
// endpoint of a binding naming it then declares, so a typed client decodes it.
export const Login = Authentication.make("notes.Login", CurrentPrincipal, {
  error: ProviderUnavailable,
});

export const Http = ActionHttp.make([List, Write, Whoami], { authentication: Login });
```

The server declares the resource once, at module level, from that descriptor, every scope it has and the one every credential must carry, `required`, one of `scopes` as the types check. It provides its `layer` and its `provider` once at application construction, never per request. `Resource.make` takes only a descriptor declaring `ProviderUnavailable`: one that does not is a type error there, naming `error: ProviderUnavailable`.

```ts
import { Layer } from "effect";
import { FetchHttpClient } from "effect/http";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import { Http, Login } from "./contracts.ts";

// The application's resource: the descriptor's name is its service's, unique in the process.
export const NotesResource = Resource.make(Login, {
  scopes: ["notes:read", "notes:write"], // every scope it has, published in discovery
  required: "notes:read", // every credential must carry it; every 401 names it
});

// `app` is your implementation, behind your own authorizer, a module-level value: see
// "Scope enforcement".
const routes = Layer.mergeAll(
  ActionHttp.layer(Http, [app, NotesResource.session]),
  ActionMcp.layerHttp(app, { name: "notes", version: "1.0.0", authentication: Login }),
).pipe(
  Layer.provide(NotesResource.provider),
  Layer.provide(
    NotesResource.layer({
      issuer: "https://clankerauth.internal/api/auth",
      publicUrl: new URL("https://notes.internal"),
    }),
  ),
  Layer.provide(FetchHttpClient.layer),
);
```

Serve this layer with Effect's `HttpRouter` and your Node server layer. If using `@effect/platform-node`, install the release that matches your Effect. The scopes are the same in every deployment, so they are declared with the resource; `NotesResource.layer` takes what varies by deployment and builds the resource once: its verifier and refusals. `NotesResource.provider` is the descriptor's provider, effect-actions' `Authentication.layer`: it verifies every protected route and tool call before decoding, and publishes discovery itself, public and outside authentication; there is no discovery route to merge. Discovery cache policy belongs to the host. Every response to a request it authenticates carries `Cache-Control: no-store`. Middleware of your own runs as effect-actions runs it: router middleware provided after the provider, or an HTTP layer's `middleware`.

A surface whose callers hold API keys and never run an OAuth flow, such as a second listener beside the one that publishes the resource, sets `discovery: false`: it authenticates the same way, publishes nothing, and its challenge is a plain `Bearer`.

A process serving two resources, such as two listeners with different scopes, declares two descriptors and two resources: `Resource.make(Authentication.make("notes.admin", CurrentPrincipal, { error: ProviderUnavailable }), { scopes: ["notes:read", "notes:write"], required: "notes:read" })` and one for `"notes.machine"`, each named by its own binding. Each is a service of its own, so each surface reads its own resource, in one layer graph or several. The descriptor's name is the identity: declaring one name twice declares the same resource twice.

A declared resource is a `Resource.Declared<"notes.Login">`, and what its `layer` builds a `Resource.Built`; its descriptor is a `Resource.Login<"notes.Login">`. `Declared` and `Login` take what the descriptor declares as an optional second parameter, `ProviderUnavailable` alone when left out. `Declared` and `Built` take the resource's scopes as an optional parameter, last, which `make` infers from `scopes`: an annotation that leaves it out accepts any scope string. The entry point also exports each type a resource's declarations mention under a flat name (`DeclaredResource`, `BuiltResource`, `ResourceService`, `ResourceDeclaration`, `ResourceOptions`, `Login`, `Admission`, `Refusal`, `Principal`, `Verifier`); `CurrentPrincipal` and its `Caller` are `/session`'s, where declarations name them. So a package that exports its descriptor, its resource or its implementations emits declarations without an annotation.

The supplied `HttpClient` must not retry credential exchanges or follow redirects. The SDK overrides only FetchHttpClient's redirect policy to reject redirects, preserves other caller-provided fetch defaults, and never installs retry middleware.

## Scope enforcement

The application decides which scope an action needs; the SDK verifies the credential and offers the check. Verification requires `required` of every credential, so an action that needs nothing more passes. Any other scope is the application's rule, stated as its implementation's authorizer with `requires(scope)`: it runs after the input is decoded and before every handler on every surface — HTTP, MCP, Toolkit, CLI — so no handler can forget it.

```ts
import { Effect } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import { CurrentPrincipal } from "@gjermundgaraba/clankerauth-sdk/session";

const List = Action.make("list", {
  description: "List notes",
  readOnly: true,
  caller: CurrentPrincipal,
  success: Notes,
});

const Write = Action.make("write", {
  description: "Write a note",
  readOnly: false,
  caller: CurrentPrincipal,
  success: Note,
});

// The application's rule: a read needs only what verification required, a write needs
// `notes:write`. It reads no built resource, so this is a module-level value.
const authorize = (action: Action.Any) =>
  action.readOnly ? Effect.void : NotesResource.requires("notes:write");

const app = Action.implement([List, Write], handlers, { authorize });
```

`requires(scope)` takes one of the resource's declared scopes, so a typo, `requires("notes:wirte")`, is a type error, as it is in `admitted`, `admit` and `watch`. It is an `Effect<void, Action.Forbidden, CurrentPrincipal>`: a caller without the scope is refused with a `Forbidden` (403) naming **only** that scope, so it never enumerates the resource's permissions. A single-scope resource, `{ scopes: ["notes:read"], required: "notes:read" }`, has nothing more to require: its implementations state `{ authorize: Action.allowAll }`. Each scope is an OAuth scope token, printable ASCII without spaces, `"` or `\`: effect-actions refuses one that is not when the provider builds the discovery it publishes. With `discovery: false` nothing checks them, and refusing an OAuth client for a declared scope that is no scope token is a defect, a 500: `Action.Forbidden`'s constructor throws on it.

A trusted local surface, such as stdio MCP or a local command, has no remote caller and no credential to verify. The process is the caller: `NotesResource.local(subject)` is its principal, `{ kind: "local" }`, holding every scope the resource declares and never expiring. The host provides it as effect-actions provides any local identity, and serves the same implementation, whose authorizer admits it, as it holds every scope:

```ts
const stdio = ActionMcp.runStdio(app, { name: "notes", version: "1.0.0" }).pipe(
  Effect.provide(NodeStdio.layer),
  Effect.provideService(CurrentPrincipal, NotesResource.local("owner")),
);
```

On a local `ActionCli` command, `Command.provideSync(CurrentPrincipal, NotesResource.local("owner"))`. A local surface builds no resource: `local` and `requires` read only the declared scopes and the caller.

A forward-auth browser token carries **every** scope the resource defines, because the issuer mints it for the signed-in owner and not for a program. A scope the application requires therefore gates agents and API keys, not the owner at a keyboard: give a read-only agent or key only `notes:read` and the same rule refuses its writes.

An action reads identity from `CurrentPrincipal`, a `Caller`, which contains `subject`, `scopes`, `actor` — `{ kind: "client", clientId }`, `{ kind: "key", keyId }`, or `{ kind: "local" }` for the process on a local surface — and `expiresAt`: an access token's verified `exp`, or an API key's expiry, in epoch milliseconds, so a host bounding a connection to its credential never decodes it again. It is `undefined` for a key that does not expire and for a local principal. A key can also be revoked before then; `watch`, below, ends a connection at whichever comes first. What a verifier proves, `Verifier.Principal`, is a client or a key only: it is what `verifyToken` and `admit` give, and every one is a `Caller`.

Every refusal is one of effect-actions' built-in errors, which every endpoint and tool declares and every client decodes: `Unauthenticated` (401) and `Forbidden` (403). An access token's `Forbidden` names the missing scope, and is answered, over MCP too, as a 403 with an `insufficient_scope` challenge an OAuth client steps up on. An API key cannot re-authorize, so its `Forbidden` names none: a plain 403, and a tool error over MCP. `Cache-Control: no-store` and the challenges come from effect-actions, around every request the provider authenticates. A request without a bearer token is refused before the verifier runs: `A bearer token is required.`

The provider authenticates the request and the application's authorizer authorizes it; neither filters MCP tool discovery.

## Routes of your own

A route the application serves itself, beside its actions, such as a page frame, a file download or an OpenAPI document, is admitted as the actions are with `admitted`, router middleware provided around it:

```ts
import { Effect, Layer } from "effect";
import { HttpRouter, HttpServerResponse } from "effect/http";
import { CurrentPrincipal } from "@gjermundgaraba/clankerauth-sdk/session";

const frame = HttpRouter.add(
  "GET",
  "/frame",
  Effect.map(CurrentPrincipal, ({ subject }) => HttpServerResponse.text(subject)),
).pipe(Layer.provide(NotesResource.admitted().layer));
```

`admitted()` admits any verified caller; `admitted("notes:write")` also checks that scope inside it, with `requires`, as an authorizer checks an action's. It is effect-actions' `Authentication.protect` with the resource's descriptor, an `Authentication.Protection`, so the route is answered exactly as an action route answers the same request: a refusal with the same status, challenge, `Cache-Control` and JSON, the 503 when the issuer is unavailable, `Cache-Control: no-store` on every response unless the route states its own caching, and a refusal the route fails with itself, `Unauthenticated` or `Forbidden`, or a 401 it answers, with its challenge. An admitted route reads its caller from `CurrentPrincipal`. Its layer requires the resource's `provider`, which authenticates it: provide `provider` around the admitted routes as around the actions, once for both. It is Effect's own `HttpRouter.Middleware`, so `combine` composes middleware of your own reading the caller inside it: `myMiddleware.combine(NotesResource.admitted())`.

## Outside the router

A socket, a Node `upgrade` handler or a per-request endpoint, which holds a header and no routed request, verifies the same credential against the same resource, and renders the same refusal, with `admit`. Any verified caller is admitted, or with a scope, only one that also holds it:

```ts
// `notes` is the built resource: `yield* NotesResource.service`, under `NotesResource.layer`.
const admission = await Effect.runPromise(
  notes.admit(request.headers.authorization, "notes:write"),
);

if (!admission.ok) {
  const { status, headers, body } = admission.refusal;
  response.writeHead(status, headers).end(body);
  return;
}

connect(admission.principal);
```

The refusal carries each error's own status (401/403/503), the RFC 6750 challenge including the no-credential case, `Cache-Control: no-store`, and the error's JSON encoding. It is `admitted`'s check, rendered by effect-actions' `Authentication.refusalResponse`, the answer a route gets for the same refusal, so a router and a socket can never answer differently. `admission.principal` is a `Verifier.Principal`, a client or a key.

A connection that outlives its admission, such as a WebSocket, is held to the same header value and scope with `watch`. It fails with the refusal `admit` would then answer, `Action.Refusal` or `ProviderUnavailable`: once an access token expires, or once a refreshed key list no longer grants the key, or no longer grants the scope. It never succeeds, so race it against the connection:

```ts
const session = Effect.raceFirst(
  serve(socket),
  notes.watch(request.headers.authorization, "notes:write"),
);
```

An access token cannot be revoked, so `watch` waits for its expiry and then fails `Unauthenticated`, without asking the issuer again; a key is re-checked about once a minute against the list the resource last read, which is itself read about once a minute, so a revoked key ends a watched connection within about two minutes. A key needs the issuer only once that list is past its window.

The resource also exposes `verifier.verifyToken(token)` as an Effect for callers that render their own responses; it takes the token, not the header, which effect-actions' `Authentication.bearerTokenOf(authorization)` reads as every surface does. A provider of your own, effect-actions' `Authentication.layer` around a verifier of your own, starts from `Resource.authenticate(verifier, token)`, given the token the descriptor's scheme decodes: the principal, the refusal a surface sends, or `ProviderUnavailable`, which your descriptor declares too, so a surface sends it as the 503.

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

A browser page holds no credential of its own: put it behind a reverse proxy with the issuer's forward auth, described in the clankerauth README, and the proxy adds the `Authorization` header this package verifies. What the page does need is who it is signed in as, and a way out:

```ts
import { Principal, Whoami, signOutUrl } from "@gjermundgaraba/clankerauth-sdk/session";

// `Whoami` is the contract, bound beside your own actions; the server answers it with
// its resource's `session`. `api` is `ActionHttp.fetchClient(Http)`.
const principal: Principal = await Effect.runPromise(api.whoami());
link.href = signOutUrl(principal.issuer, `${location.origin}/`);
```

`Principal` is `{ subject, issuer, scopes }`. `signOutUrl` points at the issuer's `/forward-auth/logout?rd=…`, which ends the issuer session and every app's forward cookie; it is a plain link. On the server, a declared resource's `session`, `NotesResource.session`, is `Whoami` already implemented from the verified credential — pass it to `ActionHttp.layer` beside your own implementation, and delete the hand-written `whoami`.

## A fake issuer for tests

`@gjermundgaraba/clankerauth-sdk/testing` is the issuer an application test usually wants: the two endpoints a resource server actually calls, and nothing else. It signs with a real EdDSA key and publishes it as JWKS, so every token and key list still travels the resource server's own verifier — signature, issuer, audience, type, claims, scopes, each key's sealed entry — without starting the whole issuer. It runs on Node.

```ts
import { startFakeIssuer } from "@gjermundgaraba/clankerauth-sdk/testing";

const auth = await startFakeIssuer({
  resource: "http://127.0.0.1:8080/",
  scopes: ["notes:read", "notes:write"],
});

auth.issuer; // configure the resource server with this
const token = await auth.sign(); // every claim is overridable: auth.sign({ exp, aud, scope })
const key = auth.apiKey(); // every configured scope on the configured resource
const hosts = auth.apiKey({ [hostA]: ["host:write"], [hostB]: ["host:write"] }, expiresAt);
auth.revoke(key); // gone from the next key list, as the real issuer behaves
auth.fail(503); // both endpoints answer this instead; auth.fail() restores them
auth.keyLists(); // how many key lists were served
await auth.close();
```

`apiKey` takes permissions as the real issuer does, resource identifier to scopes, so one key can reach several resources. A resource server reads its key list once a minute for the keys it names, so a test that revokes a key and expects a refusal verifies with a fresh verifier, or advances its clock past that minute. A key minted after a verifier's read is refused until that read is five seconds old, so a test mints its keys before its first request. To test against the whole issuer — sign-in, consent, forward auth — use `@gjermundgaraba/clankerauth-dev`.

## Errors and observability

Tagged errors, all from `@gjermundgaraba/clankerauth-sdk/errors`: `Unauthorized`, `InsufficientScope` and `ProviderUnavailable` are what the `Verifier` fails with. Only `ProviderUnavailable` (503) is a schema, which a resource's descriptor declares and every protected endpoint of a binding naming it then declares; the first two never reach the wire, as a `Resource` sends them as effect-actions' built-in `Unauthenticated` (401) and `Forbidden` (403). Invalid construction, such as an issuer that is no URL, fails with `ConfigurationError`.

There is one 403. Only the verifier's own check fails with `InsufficientScope`: a credential that is valid but lacks a scope in `requiredScopes`, a resource's `required`. It names that scope and the credential's `actor`, which decides whether its `Forbidden` steps up. A scope asked for after verification, by `requires(scope)`, `admitted(scope)`, `admit(header, scope)` or `watch(header, scope)`, is refused with effect-actions' `Action.Forbidden` directly, decided by the same rule. A credential that is not this resource's at all — the wrong audience, or an API key with no entry in this resource's key list — is `Unauthorized`, because from the resource's side those are the same thing.

JWTs are checked against issuer, audience, EdDSA signature, token type, required claims, expiry and scopes. Sender-constrained tokens are rejected. One JWKS read answers every verification for a minute, so a key the issuer starts or stops publishing takes effect within that minute; a `kid` the current document does not publish is `Unauthorized` and never triggers a read, so a token with an invented `kid` cannot become provider traffic. A failed read, or one whose caller gave up, answers `ProviderUnavailable` (503) for five seconds before the next attempt. API keys are verified offline, against the resource's key list: one document the issuer signs with its access-token key, holding a sealed entry per key granted on this resource, which only that key can find or open. The list is verified once, when it is read, and one read answers every key it names for a minute, without issuer traffic; so a key disabled, deleted or re-scoped keeps the access it had until the next read, within about a minute. A key the held list does not name may have been created, enabled or granted on this resource since, so the list is read again before the key is refused, unless it was read within the last five seconds: such a key works within seconds, and unknown keys reach the issuer at most once every five seconds. A key's own expiry is checked on every verification, so it applies at once. A failed read, one that takes longer than three seconds, or one whose caller gave up, is no error while the last list is inside its own lifetime, which the issuer sets to 24 hours: keys keep verifying through an outage, JWKS or not, and the issuer is tried again after five seconds. Past that lifetime, or before any list has been read, a key is `ProviderUnavailable`. Reads that start failing are logged once as a warning, and their recovery once at info level, so an outage the held list hides still shows in the application's logs without a line per retry. The last list read is the one held, whatever its `iat`: HTTPS to the issuer is what keeps an old list from being replayed, and one could only ever be replayed inside its own day. The issuer does not count key use, so rate limiting is the application's. A key is a bearer secret, and one granted on several resources can be replayed by any of them to the others; a resource you trust less gets its own key. A resource that accepts only OAuth access tokens sets `apiKeys: false`; key-shaped bearers then fail as `Unauthorized` without reading the key list. Admission through a `Resource` has a five-second deadline; the raw `Verifier` has none, so an in-process caller can await a provider call it cannot cancel. The exception is the key list read's own three seconds: shorter than that deadline, so an issuer that stops answering delays a key by at most that long, never fails it while a list is held.

The bundled issuer does not configure automatic signing-key rotation. Immediate-use rotation is supported, but tokens signed by a new key are rejected until the next JWKS read, up to a minute; a key list signed by it is not taken until then either, and the held list keeps deciding. Publish-before-use avoids that window; it is not mandatory. Key lists are re-signed on every read, so issued API keys are unaffected by rotation.

The SDK's resource maps verification failures to effect-actions' refusals and its own 503; effect-actions supplies request-scoped identity, challenge headers and `Cache-Control: no-store` on every response to a request it authenticates; other cache policy is the host's. Defects and interruption are not relabeled as authentication rejection. Named effects supply tracing boundaries; application logging/tracing layers remain caller-owned. No `onFailure` callbacks or hidden runtime.

Operational failures retain their underlying `cause` for application-side Effect error handling. `ProviderUnavailable` and `Unauthorized` keep this diagnostic field non-enumerable, outside what is serialized. Causes may contain sensitive transport or provider details: inspect selectively, never serialize them into responses or log them indiscriminately.

MIT licensed.
