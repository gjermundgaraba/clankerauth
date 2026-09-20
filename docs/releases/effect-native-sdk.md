# Effect-native Node SDK (unreleased, breaking)

The Node SDK uses Effect `4.0.0-rc.116`, with optional effect-actions integration. It no longer supports the standalone Promise API.

## Removed

- `createVerifier`, `createBrowserSession` and Promise-based session-store contracts.
- `AuthError` / `IssuerResponseError` and `onFailure` callbacks.
- SDK-owned `metadataUrl`, `challenge`, `protectedResourceMetadata`, `failureResponse`.
- Web Request/Response handler contracts and framework compatibility paths.

## Replacement

- `Verifier.make`: standalone Effect-native token and API-key verification from the core entrypoint.
- `Resource.make` from `/effect-actions`: Effect acquisition of a resource-bound verifier and effect-actions discovery. `Resource.middleware(resource, { browser? })` authenticates bearer tokens, or the session cookie when `browser` is given and no Authorization header is present. `apiKeys: false` declares a resource that accepts only OAuth access tokens.
- `CurrentPrincipal` from `/effect-actions`: request-scoped identity for actions.
- `BrowserSession.make` and `SessionStore`: Effect-native session workflows and persistence, accepting only the `verifyToken` function they need. Browser configuration now requires `callbackUrl` instead of `origin`; the origin and cookie security are derived from that validated HTTP(S) URL.
- `BrowserActions.layer` from `/effect-actions`: login, session and logout actions under `/auth/browser`. The callback alone is a protocol HTTP route. Browser bundles import pure contracts from `/browser-api`.
- Schema-tagged failures with HTTP annotations instead of exception codes.

Successful JWKS lookups last ten minutes. Unknown signing keys trigger one coordinated refresh and resolution retry, with a thirty-second cooldown after successful lookups and miss-triggered refresh attempts. Failed refreshes return 503 during the cooldown without discarding valid cached keys; initial lookup failures remain retryable. Immediate-use rotation can encounter this short cooldown but no longer requires ten-minute publish-before-use. The bundled issuer has automatic rotation disabled.

Core imports do not load or require effect-actions. Install its optional peer dependency when using `/effect-actions` or `/browser-api`; both core and integration declarations are validated without `skipLibCheck` against the workspace's local effect-actions build.

Missing or invalid authorization endpoints are rejected at discovery as sanitized provider failures rather than escaping as defects. Malformed or unsupported browser callback URLs fail construction with `ConfigurationError`.

`BrowserActions.layer` mounts the callback at the configured URL's pathname; login and code exchange use that exact URL, including any query parameters. Return destinations exclude the callback pathname rather than the whole `/auth/` namespace.

Redirect rejection preserves application-provided FetchHttpClient defaults such as headers and cache policy.

Operational errors retain internal diagnostic causes while public error schemas omit them.

Supply HttpClient and persistence at application composition. No implicit runtime or environment configuration. Promise bridges remain only inside third-party OAuth/cryptographic boundaries.

## Preserved intentionally

Refresh no-replay markers, callback consumption, origin checks, PKCE/state/nonce checks, exact audience/issuer verification, signed ID-token validation and encrypted storage remain load-bearing safeguards.

Operational refresh errors now remain 503 outcomes rather than being disguised as invalid credentials. The session is invalidated after an uncertain exchange; interruption leaves the durable marker. Subsequent access requires sign-in. Discovery failures before exchange do not consume a refresh credential.

External consuming repositories were intentionally not changed. Migrate their dependency versions, composition roots, error handling and persistence adapters before adopting this release. Remove Promise/Effect round trips rather than wrapping the retired API.

See [the package README](../../packages/node/README.md) for integration examples. The issuer verifies administration MCP tokens with this SDK; its dashboard keeps the issuer session.
