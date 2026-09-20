import { Context, Effect, Match, Schema, type Scope } from "effect";
import { HttpServerRequest } from "effect/unstable/http";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { CurrentPrincipal, type Resource } from "@gjermundgaraba/clankerauth-node/effect-actions";
import { Unauthorized } from "@clankerauth/api";
import { apiError, apiErrorResponse, provider } from "./api-errors.ts";
import { providerSession } from "./provider-session.ts";
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

const fail = (error: ReturnType<typeof apiError>) =>
  Effect.flatMap(apiErrorResponse(error), Effect.fail);

/** Dashboard HTTP: the issuer's SameSite session cookie. */
export const sessionOwner = (service: Service) =>
  Authentication.middleware(
    CurrentOwner,
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const headers = new Headers(request.headers);
      const session = yield* provider(() => service.auth.api.getSession({ headers }));

      if (!session)
        return yield* Effect.fail(new Unauthorized({ error: "Owner session required" }));

      return {
        providerHeaders: Effect.succeed(headers),
        userId: session.user.id,
        email: session.user.email,
      };
    }).pipe(Effect.catch(fail)),
  );

const OwnerRow = Schema.Struct({ id: Schema.String, email: Schema.String });

/** MCP: combine with the resource middleware that verifies the bearer token and
 * supplies CurrentPrincipal. The token's client must still exist and not be blocked;
 * revocation of already-issued access tokens takes effect at their expiry.
 */
export const bearerOwner = (service: Service, resource: Resource.Resource) => {
  const rejected = () => new Unauthorized({ error: "Owner authorization required" });

  return Authentication.middleware(
    CurrentOwner,
    Effect.gen(function* () {
      const principal = yield* CurrentPrincipal;

      if (principal.actor.kind !== "client") return yield* Effect.fail(rejected());

      const rows = yield* service.sql`SELECT u.id, u.email FROM user u
      JOIN oauthClient c ON c.clientId = ${principal.actor.clientId}
      WHERE u.id = ${principal.subject} AND c.disabled IS NOT 1`.pipe(Effect.mapError(apiError));

      if (!rows[0]) return yield* Effect.fail(rejected());

      const owner = yield* Schema.decodeUnknownEffect(OwnerRow)(rows[0]).pipe(
        Effect.mapError(apiError),
      );

      return {
        userId: owner.id,
        email: owner.email,
        providerHeaders: providerSession(service, owner.id),
      };
    }).pipe(
      Effect.catch((error) =>
        Effect.flatMap(
          apiErrorResponse(
            error,
            Match.value(error).pipe(
              Match.tag("Unauthorized", () => resource.challenge("invalid_token")),
              Match.orElse(() => ({})),
            ),
          ),
          Effect.fail,
        ),
      ),
    ),
  );
};
