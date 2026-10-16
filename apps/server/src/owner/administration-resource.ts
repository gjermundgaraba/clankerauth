import {
  administrationScopes,
  administrationIdentifier,
} from "@gjermundgaraba/clankerauth-admin-api";
import { Effect, Layer } from "effect";
import type * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { FetchHttpClient } from "effect/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import { Issuer } from "../issuer/issuer.ts";
import { peerHeader } from "../platform/node-http.ts";
import { protocolScopes } from "../resources/catalog.ts";
import { Settings } from "../issuer/settings.ts";

export const administrationResource = Effect.fn("AdministrationResource.make")(function* () {
  const { auth } = yield* Issuer;
  const { baseURL } = yield* Settings;
  const issuer = `${baseURL}/api/auth`;
  const resource = administrationIdentifier(baseURL);

  const protectedResource = {
    resource,
    authorizationServers: [issuer],
    scopesSupported: [administrationScopes.read, administrationScopes.write, ...protocolScopes],
    scopesRequired: [administrationScopes.read, administrationScopes.write],
  } satisfies Authentication.ProtectedResource;

  // why: the raw verifier has no deadline, so shutdown can wait for every provider call
  const loopback: typeof fetch = (input, init) => {
    const request = new Request(input, init);
    // why: Better Auth reads the client address from this header
    request.headers.set(peerHeader, "127.0.0.1");

    return auth.handler(request);
  };

  const verifier = yield* Verifier.make({
    issuer,
    resource,
    apiKeys: false,
  }).pipe(
    Effect.provide(
      FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, loopback))),
    ),
  );

  return { protectedResource, verifier };
});

export type AdministrationResource = Effect.Success<ReturnType<typeof administrationResource>>;
