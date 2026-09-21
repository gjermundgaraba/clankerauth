/**
 * The issuer's own OAuth resource: its administration MCP endpoint, `<baseURL>/mcp`.
 *
 * An application behind this issuer registers one resource at its public origin root, and
 * the SDK's `Resource` derives exactly that. The issuer is not such an application: `/` is
 * the dashboard, authenticated by the owner's session cookie and never an OAuth audience.
 * So this builds discovery and admission from the SDK's verifier directly, and answers in
 * the issuer's own error vocabulary, the same one every other route here uses.
 */
import { Effect, Layer, Match } from "effect";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { FetchHttpClient } from "effect/unstable/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import type { AuthenticationError } from "@gjermundgaraba/clankerauth-sdk/errors";
import {
  Forbidden,
  ServiceUnavailable,
  TooManyRequests,
  Unauthorized,
} from "@clankerauth/admin-api";
import { mcpResource, mcpScope } from "./resources.ts";
import type { Service } from "./auth.ts";

export const administrationResource = Effect.fn("AdministrationResource.make")(function* (
  service: Service,
) {
  const issuer = `${service.settings.baseURL}/api/auth`;
  const resource = mcpResource(service.settings.baseURL);

  const discovery = Authentication.protectedResource({
    resource,
    authorizationServers: [issuer],
    scopesSupported: [mcpScope, "offline_access"],
  });

  // The SDK verifier reads JWKS from this issuer in-process. Provider calls are
  // tracked for shutdown like external ones: the SDK's deadline can abandon a
  // call that must still settle.
  const loopback: typeof fetch = (input, init) => {
    const request = new Request(input, init);
    // Better Auth reads the client address from this header (see ipAddressHeaders in auth.ts).
    request.headers.set("x-clankerauth-peer", "127.0.0.1");

    return service.run(() => service.auth.handler(request));
  };

  const verifier = yield* Verifier.make({
    issuer,
    resource,
    requiredScopes: [mcpScope],
    // The loopback serves provider routes only, so key verification must never reach the issuer.
    apiKeys: false,
  }).pipe(
    Effect.provide(
      FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, loopback))),
    ),
  );

  /** One verification failure as this issuer's public error and its RFC 6750 challenge. */
  const refuse = (error: AuthenticationError, credential: boolean) =>
    Match.value(error).pipe(
      Match.tag("InsufficientScope", ({ scope }) => ({
        error: new Forbidden({ error: "Insufficient scope" }),
        headers: {
          "www-authenticate": discovery.challenge({ error: "insufficient_scope", scope }),
        },
      })),
      Match.tag("RateLimited", () => ({
        error: new TooManyRequests({ error: "Authentication rate exceeded" }),
        headers: { "retry-after": "60" },
      })),
      Match.tag("ProviderUnavailable", () => ({
        error: new ServiceUnavailable({ error: "Request could not be completed" }),
        headers: {},
      })),
      // RFC 6750 §3.1: a request that carried no credentials gets no error code.
      Match.tag("Unauthorized", () => ({
        error: new Unauthorized({ error: "Authentication required" }),
        headers: { "www-authenticate": challenge(credential) },
      })),
      Match.exhaustive,
    );

  /** The challenge for a request whose token was accepted but whose owner was not. */
  const challenge = (invalid: boolean) =>
    discovery.challenge(
      invalid ? { error: "invalid_token", scope: mcpScope } : { scope: mcpScope },
    );

  return { discovery, verifier, refuse, challenge };
});

export type AdministrationResource = Effect.Success<ReturnType<typeof administrationResource>>;
