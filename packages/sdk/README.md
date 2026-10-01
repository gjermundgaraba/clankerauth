# @gjermundgaraba/clankerauth-sdk

Effect-native [clankerauth](https://github.com/gjermundgaraba/clankerauth) verification. Verifies JWT access tokens and API keys, both offline, including the tokens a reverse proxy obtains through the issuer's forward auth for browser sessions. Optional **effect-actions** integration provides request-scoped identity, OAuth discovery, scope enforcement and a `session` contract a browser page can import on its own.

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
vp add @gjermundgaraba/effect-actions@^0.9.0
```

## Entry points

| Import                             | Needs effect-actions | Browser safe | What it holds                                     |
| ---------------------------------- | -------------------- | ------------ | ------------------------------------------------- |
| `…/clankerauth-sdk`                | no                   | no           | `Verifier`, `RequestPolicy`                       |
| `…/clankerauth-sdk/errors`         | no                   | **yes**      | the error schemas and `authenticationErrors`      |
| `…/clankerauth-sdk/session`        | yes                  | **yes**      | the `session` contract, `Principal`, `signOutUrl` |
| `…/clankerauth-sdk/effect-actions` | yes                  | no           | `Resource`, `CurrentPrincipal`                    |
| `…/clankerauth-sdk/key-list`       | no                   | no           | the key list format, for issuers and fakes        |
| `…/clankerauth-sdk/testing`        | no                   | no           | `startFakeIssuer`, for tests (Node only)          |

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
// Acquire once, then use verifier.verify(authorization) or verifier.verifyToken(token).
```

## One resource per application

Register **one** resource in the clankerauth dashboard, identified by the application's public origin root, written with its trailing slash: `https://notes.internal/`. That one resource covers `/api`, `/mcp` and any socket, with one RFC 9728 document at `/.well-known/oauth-protected-resource` and one `forward_auth` block in the proxy.

`Resource.make` takes the public URL and derives that identifier itself, so the application never writes it twice and never writes a form an MCP client would rewrite. Any path on the URL is discarded. The official client's own `checkResourceAllowed` accepts an origin-root resource for an endpoint beneath it.

Acquire the resource once at application construction, never per request.

```ts
import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/http";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import { authenticationErrors } from "@gjermundgaraba/clankerauth-sdk/errors";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";

// Http and app are your effect-actions HTTP binding and implemented group.
const routes = Layer.unwrap(
  Effect.gen(function* () {
    const notes = yield* Resource.make({
      issuer: "https://clankerauth.internal/api/auth",
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
        errors: authenticationErrors,
        before: notes.authorize,
      }).pipe(Layer.provide(Resource.middleware(notes).layer)),
    );
  }),
).pipe(Layer.provide(FetchHttpClient.layer));
```

Serve this layer with Effect's `HttpRouter` and your Node server layer. If using `@effect/platform-node`, install the release that matches your Effect. Discovery is public; do not wrap it in authentication. Discovery cache policy belongs to the host. Every authentication response carries `Cache-Control: no-store`.

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

An action reads identity from `CurrentPrincipal`, which contains `subject`, `scopes`, `actor` — either `{ kind: "client", clientId }` or `{ kind: "key", keyId }` — and `expiresAt`: an access token's verified `exp`, or an API key's expiry, in epoch milliseconds, so a host bounding a connection to its credential never decodes it again. It is `undefined` for a key that does not expire. A key can also be revoked before then; `watch`, below, ends a connection at whichever comes first.

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

The refusal carries each error's own status (401/403/503), the RFC 6750 challenge including the no-credential case, `Cache-Control: no-store`, and the error's JSON encoding. `Resource.middleware` is built on the same function at `"read"`, so a router and a socket can never answer differently.

A connection that outlives its admission, such as a WebSocket, is held to the same header value and access level with `watch`. It fails with the first refusal: once an access token expires, or once a refreshed key list no longer grants the key, or no longer grants the write scope. It never succeeds, so race it against the connection:

```ts
const session = Effect.raceFirst(
  serve(socket),
  notes.watch(request.headers.authorization, "write"),
);
```

An access token cannot be revoked, so `watch` waits for its expiry and then fails `Unauthorized`, without asking the issuer again; a key is re-checked about once a minute against the list the resource last read, which is itself read about once a minute, so a revoked key ends a watched connection within about two minutes. A key needs the issuer only once that list is past its window.

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

A browser page holds no credential of its own: put it behind a reverse proxy with the issuer's forward auth, described in the clankerauth README, and the proxy adds the `Authorization` header this package verifies. What the page does need is who it is signed in as, and a way out:

```ts
import { Principal, Session, signOutUrl } from "@gjermundgaraba/clankerauth-sdk/session";

// `Session` is the contract; the server answers it with `resource.session`.
const principal: Principal = await api.session.whoami({ payload: {} });
link.href = signOutUrl(principal.issuer, `${location.origin}/`);
```

`Principal` is `{ subject, issuer, scopes }`. `signOutUrl` points at the issuer's `/forward-auth/logout?rd=…`, which ends the issuer session and every app's forward cookie; it is a plain link. On the server, `resource.session` is the same group already implemented from the verified credential — pass it to the HTTP binding beside your own application, and delete the hand-written `whoami`.

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

Schema-tagged errors, all from `@gjermundgaraba/clankerauth-sdk/errors`: `Unauthorized` (401), `InsufficientScope` (403) and `ProviderUnavailable` (503), collected as `authenticationErrors`. Invalid construction fails with `ConfigurationError`.

There is one 403. A credential that is valid but lacks a scope is `InsufficientScope`; a credential that is not this resource's at all — the wrong audience, or an API key with no entry in this resource's key list — is `Unauthorized`, because from the resource's side those are the same thing.

JWTs are checked against issuer, audience, EdDSA signature, token type, required claims, expiry and scopes. Sender-constrained tokens are rejected. One JWKS read answers every verification for a minute, so a key the issuer starts or stops publishing takes effect within that minute; a `kid` the current document does not publish is `Unauthorized` and never triggers a read, so a token with an invented `kid` cannot become provider traffic. A failed read, or one whose caller gave up, answers `ProviderUnavailable` (503) for five seconds before the next attempt. API keys are verified offline, against the resource's key list: one document the issuer signs with its access-token key, holding a sealed entry per key granted on this resource, which only that key can find or open. The list is verified once, when it is read, and one read answers every key it names for a minute, without issuer traffic; so a key disabled, deleted or re-scoped keeps the access it had until the next read, within about a minute. A key the held list does not name may have been created, enabled or granted on this resource since, so the list is read again before the key is refused, unless it was read within the last five seconds: such a key works within seconds, and unknown keys reach the issuer at most once every five seconds. A key's own expiry is checked on every verification, so it applies at once. A failed read, one that takes longer than three seconds, or one whose caller gave up, is no error while the last list is inside its own lifetime, which the issuer sets to 24 hours: keys keep verifying through an outage, JWKS or not, and the issuer is tried again after five seconds. Past that lifetime, or before any list has been read, a key is `ProviderUnavailable`. Reads that start failing are logged once as a warning, and their recovery once at info level, so an outage the held list hides still shows in the application's logs without a line per retry. The last list read is the one held, whatever its `iat`: HTTPS to the issuer is what keeps an old list from being replayed, and one could only ever be replayed inside its own day. The issuer does not count key use, so rate limiting is the application's. A key is a bearer secret, and one granted on several resources can be replayed by any of them to the others; a resource you trust less gets its own key. A resource that accepts only OAuth access tokens sets `apiKeys: false`; key-shaped bearers then fail as `Unauthorized` without reading the key list. Admission through a `Resource` has a five-second deadline; the raw `Verifier` has none, so an in-process caller can await a provider call it cannot cancel. The exception is the key list read's own three seconds: shorter than that deadline, so an issuer that stops answering delays a key by at most that long, never fails it while a list is held.

The bundled issuer does not configure automatic signing-key rotation. Immediate-use rotation is supported, but tokens signed by a new key are rejected until the next JWKS read, up to a minute; a key list signed by it is not taken until then either, and the held list keeps deciding. Publish-before-use avoids that window; it is not mandatory. Key lists are re-signed on every read, so issued API keys are unaffected by rotation.

The SDK Resource adapter owns authentication error encoding and challenge headers; effect-actions supplies request-scoped identity, and its authentication middleware marks every response it answers or wraps `Cache-Control: no-store`; other cache policy is the host's. Defects and interruption are not relabeled as authentication rejection. Named effects supply tracing boundaries; application logging/tracing layers remain caller-owned. No `onFailure` callbacks or hidden runtime.

Operational failures retain their underlying `cause` for application-side Effect error handling. `ProviderUnavailable` and `Unauthorized` keep this diagnostic field outside their public schemas; effect-actions serializes only those schemas. Causes may contain sensitive transport or provider details: inspect selectively, never serialize them into responses or log them indiscriminately.

MIT licensed.
