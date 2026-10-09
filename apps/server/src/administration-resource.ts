/**
 * The issuer's own OAuth resource, administration, at its origin root as an application's
 * is: `/mcp` and `/api/owner/<action>` take its tokens. The dashboard at `/` is not part of
 * it and takes the owner's session cookie alone.
 *
 * The issuer verifies its own tokens in-process, so this builds admission from the SDK's
 * verifier directly rather than through `Resource`, and effect-actions' authentication
 * publishes its discovery and challenges.
 */
import { Effect, Layer } from "effect";
import type * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { FetchHttpClient } from "effect/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import { administrationScopes, administrationIdentifier } from "./resources.ts";
import { Auth } from "./auth.ts";

export const administrationResource = Effect.fn("AdministrationResource.make")(function* () {
  const service = yield* Auth;
  const issuer = `${service.settings.baseURL}/api/auth`;
  const resource = administrationIdentifier(service.settings.baseURL);

  // Published, and named in every challenge, by the authentication around the endpoint.
  // Clients ask for what a 401 names. Naming both scopes lets the owner decide at consent
  // whether a client may change anything or only look.
  const protectedResource = {
    resource,
    authorizationServers: [issuer],
    scopesSupported: [administrationScopes.read, administrationScopes.write, "offline_access"],
    scopesRequired: [administrationScopes.read, administrationScopes.write],
  } satisfies Authentication.ProtectedResource;

  // The SDK verifier reads JWKS from this issuer in-process. The raw verifier has no
  // deadline, so the provider call is awaited by the request fiber that made it: nothing
  // detaches a provider Promise, which is what lets shutdown wait for every one.
  const loopback: typeof fetch = (input, init) => {
    const request = new Request(input, init);
    // Better Auth reads the client address from this header (see ipAddressHeaders in auth.ts).
    request.headers.set("x-clankerauth-peer", "127.0.0.1");

    return service.auth.handler(request);
  };

  const verifier = yield* Verifier.make({
    issuer,
    resource,
    // API keys never administer the issuer, and the loopback serves provider routes only.
    apiKeys: false,
  }).pipe(
    Effect.provide(
      FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, loopback))),
    ),
  );

  return { protectedResource, verifier };
});

export type AdministrationResource = Effect.Success<ReturnType<typeof administrationResource>>;
