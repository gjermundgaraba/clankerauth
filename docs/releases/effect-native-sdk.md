# Effect-native Node SDK (unreleased, breaking)

The Node SDK uses the existing Effect snapshot `9ad9891`, with optional effect-actions integration. It no longer supports the standalone Promise API.

## Removed

- `createVerifier`, `createBrowserSession` and Promise-based session-store contracts.
- `AuthError` / `IssuerResponseError` and `onFailure` callbacks.
- SDK-owned `metadataUrl`, `challenge`, `protectedResourceMetadata`, `failureResponse`.
- Web Request/Response handler contracts and framework compatibility paths.

## Replacement

- `Verifier.make`: standalone Effect-native token and API-key verification from the core entrypoint.
- `Resource.make` from `/effect-actions`: Effect acquisition of a resource-bound verifier, bearer middleware and effect-actions discovery.
- `CurrentPrincipal` from `/effect-actions`: request-scoped identity for actions.
- `BrowserSession.make` and `SessionStore`: Effect-native session workflows and persistence, accepting only the `verifyToken` function they need. Browser configuration now requires `callbackUrl` instead of `origin`; the origin and cookie security are derived from that validated HTTP(S) URL.
- `BrowserHttp.layer` / `handlers`: Effect HTTP routes; browser OAuth endpoints are not actions.
- `Resource.browserMiddleware`: explicit cookie-only authentication for HTTP groups, separate from bearer-only API/MCP routes.
- Schema-tagged failures with HTTP annotations instead of exception codes.

Successful JWKS lookups last ten minutes. Unknown signing keys trigger one coordinated refresh and resolution retry, with a thirty-second cooldown after successful lookups and miss-triggered refresh attempts. Failed refreshes return 503 during the cooldown without discarding valid cached keys; initial lookup failures remain retryable. Immediate-use rotation can encounter this short cooldown but no longer requires ten-minute publish-before-use. The bundled issuer has automatic rotation disabled.

Core imports do not load or require effect-actions. Install its optional peer dependency only when using `/effect-actions`; the preview's `skipLibCheck` requirement is confined to integration consumers.

Missing or invalid authorization endpoints are rejected at discovery as sanitized provider failures rather than escaping as defects. Malformed or unsupported browser callback URLs fail construction with `ConfigurationError`.

`BrowserHttp.layer` mounts the callback at the configured URL's pathname; login and code exchange use that exact URL, including any query parameters. Explicit handler composition supports custom deployments without fixing callbacks to `/auth/callback`. Return destinations exclude the callback pathname rather than the whole `/auth/` namespace.

Redirect rejection preserves application-provided FetchHttpClient defaults such as headers and cache policy.

Operational errors retain internal diagnostic causes while public error schemas omit them.

Supply HttpClient and persistence at application composition. No implicit runtime or environment configuration. Promise bridges remain only inside third-party OAuth/cryptographic boundaries.

## Preserved intentionally

Existing sealed payloads, identifiers and cookie names remain readable with the same secret and configuration. No storage migration or forced sign-out is required. Refresh no-replay markers, callback consumption, origin checks, PKCE/state/nonce checks, exact audience/issuer verification, signed ID-token validation and encrypted storage remain load-bearing safeguards.

Operational refresh errors now remain 503 outcomes rather than being disguised as invalid credentials. The session is invalidated after an uncertain exchange; interruption leaves the durable marker. Subsequent access requires sign-in. Discovery failures before exchange do not consume a refresh credential.

External consuming repositories were intentionally not changed. Migrate their dependency versions, composition roots, error handling and persistence adapters before adopting this release. Remove Promise/Effect round trips rather than wrapping the retired API.

See [the package README](../../packages/node/README.md) for integration examples. The issuer and dev package are not being redesigned as part of this SDK break.
