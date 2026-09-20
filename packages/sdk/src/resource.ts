import { Context, Effect } from "effect";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { HttpServerRequest } from "effect/unstable/http";
import {
  authenticationErrors,
  ConfigurationError,
  encodeError,
  Forbidden,
  RateLimited,
  Unauthorized,
} from "./errors.ts";
import type { AuthenticationError } from "./errors.ts";
import * as Verifier from "./verify.ts";

const encode = encodeError(authenticationErrors);

export class CurrentPrincipal extends Context.Service<CurrentPrincipal, Verifier.Principal>()(
  "@clankerauth/CurrentPrincipal",
) {}

export interface Options extends Verifier.Options {
  readonly scopes: readonly string[];
}

/** One resource: its verifier and discovery. Acquire once per protected audience. */
export const make = Effect.fn("Resource.make")(function* (options: Options) {
  const discovery = yield* Effect.try({
    try: () =>
      Authentication.protectedResource({
        resource: options.resource,
        authorizationServers: [options.issuer],
        scopesSupported: options.scopes,
      }),
    catch: () => new ConfigurationError({ message: "Invalid resource metadata configuration" }),
  });

  const verifier = yield* Verifier.make(options);

  const scope = options.requiredScopes?.length ? options.requiredScopes.join(" ") : undefined;

  /** Bearer challenge for this resource; no error code when the request carried no credentials. */
  const challenge = (error?: "invalid_token" | "insufficient_scope") => ({
    "www-authenticate": discovery.challenge({ error, scope }),
  });

  const headers = (error: AuthenticationError) => {
    if (error instanceof RateLimited) return { "retry-after": "60" };

    if (error instanceof Forbidden) return challenge("insufficient_scope");

    if (error instanceof Unauthorized) return challenge("invalid_token");

    return {};
  };

  return {
    verifier,
    discovery,
    challenge,
    headers,
    resource: options.resource,
    issuer: options.issuer,
  };
});

export type Resource = Effect.Success<ReturnType<typeof make>>;

/** Bearer authentication providing `CurrentPrincipal`. */
export const middleware = (resource: Resource) =>
  Authentication.middleware(
    CurrentPrincipal,
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;

      return yield* resource.verifier.verify(request.headers.authorization);
    }).pipe(
      Effect.catch((error) =>
        Effect.gen(function* () {
          const request = yield* HttpServerRequest.HttpServerRequest;

          // RFC 6750 §3.1: a request that carried no credentials gets no error code.
          const headers =
            error instanceof Unauthorized && request.headers.authorization === undefined
              ? resource.challenge()
              : resource.headers(error);

          return yield* Effect.flatMap(encode(error, headers), Effect.fail);
        }),
      ),
    ),
  );
