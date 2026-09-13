# @gjermundgaraba/clankerauth-node

Everything a Node service needs to authenticate against a [Clanker Auth](https://github.com/gjermundgaraba/clankerauth) issuer: verification of access tokens and API keys, RFC 9728 protected-resource metadata with discovery challenges, and browser login as a confidential client that keeps tokens on the server behind an HttpOnly cookie. Plain Promises over Web `Request` and `Response`; no framework.

It is published to GitHub Packages, which needs a GitHub token with the `read:packages` scope even for public packages. Map the scope in the project `.npmrc` and keep the credential in your user-level `~/.npmrc`:

```sh
echo '@gjermundgaraba:registry=https://npm.pkg.github.com' >> .npmrc
echo '//npm.pkg.github.com/:_authToken=${GH_TOKEN}' >> ~/.npmrc
npm install @gjermundgaraba/clankerauth-node
```

## Verify requests

Register one **Resource** per protected target in the dashboard, for example `https://notes.internal/api` and `https://notes.internal/mcp`. A verifier is bound to one resource and accepts either an EdDSA access token whose audience is that resource or a `ca_` API key with scopes on it. Access tokens verify offline through the issuer's JWKS; API keys verify online on every request, so disabling a key takes effect on the next one.

```ts
import {
  createVerifier,
  failureResponse,
  protectedResourceMetadata,
} from "@gjermundgaraba/clankerauth-node";

const api = { resource: "https://notes.internal/api", scopes: ["notes:read", "notes:write"] };
const verifier = createVerifier({
  issuer: "https://auth.internal/api/auth",
  resource: api.resource,
  requiredScopes: ["notes:read"],
});

// GET /.well-known/oauth-protected-resource/api
protectedResourceMetadata({ ...api, issuer: "https://auth.internal/api/auth" });

// Any protected route
try {
  const principal = await verifier.verify(request.headers.get("authorization"));
  // principal.subject is the owner; principal.actor is the client or key that acted
  if (!principal.scopes.includes("notes:write")) throw new AuthError("forbidden");
} catch (error) {
  if (error instanceof AuthError)
    return failureResponse(error, { ...api, scopes: ["notes:write"] });
  throw error;
}
```

`AuthError.code` is `unauthorized`, `forbidden`, `rate_limited` or `unavailable`, and `status` is the matching HTTP status. `failureResponse` adds the `WWW-Authenticate` challenge that points clients at the resource metadata, which is how MCP clients find the issuer.

## Browser login

Register a confidential client whose redirect URI is `<origin>/auth/callback`. The browser session runs authorization code with PKCE against the issuer, stores the sealed tokens through your store, and sets `<name>_session` as an HttpOnly cookie for 30 days. Because owner-registered clients are first party, a signed-in owner is redirected straight back with no consent screen: sign-in at one application is sign-in at all of them.

```ts
import { createBrowserSession } from "@gjermundgaraba/clankerauth-node";

const browser = createBrowserSession({
  issuer: "https://auth.internal/api/auth",
  clientId: process.env.AUTH_CLIENT_ID,
  clientSecret: process.env.AUTH_CLIENT_SECRET,
  origin: "https://notes.internal",
  resource: api.resource,
  scopes: api.scopes,
  secret: process.env.SESSION_SECRET, // at least 32 characters
  store, // get, put, delete, sweep over { payload, expires } rows keyed by id
  cookie: { name: "notes" },
  verifyToken: verifier.verifyToken,
});
```

Route `POST /auth/login`, `GET /auth/callback`, `GET /auth/session` and `POST /auth/logout` to the handlers of the same name. The login handler takes `{ "returnTo": "/path" }` and answers `{ "url": … }` for the browser to navigate to; the callback redirects to `returnTo`, or to `/?auth_error=login_failed` or `/?auth_error=unavailable`. For cookie-bearing requests to your API, call `accessToken(request)` and pass the result to `verifyToken`; it refreshes serialized per session and throws `AuthError` when the user must sign in again. Mutations authenticated by cookie should also check that `Origin` matches your origin. Logout revokes the refresh token at the issuer and clears the cookie.

The store owns persistence and nothing else: payloads are sealed with AES-256-GCM under a key derived from `secret`, and ids are hashes of cookie values. Run one process per store.

MIT licensed.
