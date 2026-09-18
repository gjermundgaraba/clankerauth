import { Context, Effect } from "effect";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { HttpServerRequest } from "effect/unstable/http";
import {
  authenticationErrors,
  ConfigurationError,
  Forbidden,
  RateLimited,
  Unauthorized,
} from "./errors.ts";
import type { AuthenticationError } from "./errors.ts";
import * as Verifier from "./verify.ts";
import type { BrowserSession } from "./browser.ts";

export class CurrentPrincipal extends Context.Service<CurrentPrincipal, Verifier.Principal>()(
  "@clankerauth/CurrentPrincipal",
) {}

export interface Options extends Verifier.Options {
  readonly scopes: readonly string[];
}

/** One resource, one verifier and bearer-only middleware for HTTP actions or MCP. */
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

  const headers = (error: AuthenticationError) => {
    if (error instanceof RateLimited) return { "retry-after": "60" };

    if (error instanceof Unauthorized || error instanceof Forbidden)
      return {
        "www-authenticate": discovery.challenge({
          error: error instanceof Forbidden ? "insufficient_scope" : "invalid_token",
          scope: options.requiredScopes?.length ? options.requiredScopes.join(" ") : undefined,
        }),
      };

    return {};
  };

  const middleware = Authentication.middleware(CurrentPrincipal, {
    authenticate: Effect.flatMap(HttpServerRequest.HttpServerRequest, (request) =>
      verifier.verify(request.headers.authorization),
    ),
    errors: authenticationErrors,
    headers,
  });

  return {
    verifier,
    middleware,
    discovery,
    headers,
    resource: options.resource,
    issuer: options.issuer,
  };
});

export type Resource = Effect.Success<ReturnType<typeof make>>;

/** Opt-in browser-only HTTP authentication. Never attach this to MCP. */
export const browserMiddleware = (resource: Resource, browser: BrowserSession) =>
  Authentication.middleware(CurrentPrincipal, {
    authenticate: Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;

      if (!["GET", "HEAD", "OPTIONS"].includes(request.method))
        yield* browser.checkOrigin(request.headers.origin);
      const token = yield* browser.accessToken(request.cookies[`${browser.cookie.name}_session`]);

      return yield* resource.verifier.verifyToken(token);
    }),
    errors: authenticationErrors,
    headers: resource.headers,
  });
