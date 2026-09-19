import { Context, Effect, type Scope } from "effect";
import { HttpServerRequest } from "effect/unstable/http";
import { Forbidden, Unauthorized } from "@clankerauth/api";
import { apiError, apiErrorResponse } from "./api-errors.ts";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import type { Service } from "./auth.ts";

/** Authenticated per request, never supplied by action arguments or at startup. */
export class CurrentOwner extends Context.Service<
  CurrentOwner,
  {
    readonly userId: string;
    readonly email: string;
    readonly providerHeaders: Effect.Effect<Headers, ReturnType<typeof apiError>, Scope.Scope>;
  }
>()("ClankerAuth/CurrentOwner") {}

export const ownerAuthentication = (service: Service) =>
  Authentication.middleware(
    CurrentOwner,
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const headers = new Headers(request.headers);

      const session = yield* Effect.tryPromise({
        try: () => service.auth.api.getSession({ headers }),
        catch: apiError,
      });

      if (!session)
        return yield* Effect.fail(new Unauthorized({ error: "Owner session required" }));

      // Browser navigation to OpenAPI can omit Origin. Mutating HTTP actions cannot.
      if (request.method !== "GET" && request.headers.origin !== service.settings.baseURL)
        return yield* Effect.fail(new Forbidden({ error: "Invalid origin" }));

      return {
        providerHeaders: Effect.succeed(headers),
        userId: session.user.id,
        email: session.user.email,
      };
    }).pipe(Effect.catch((error) => Effect.flatMap(apiErrorResponse(error), Effect.fail))),
  );
