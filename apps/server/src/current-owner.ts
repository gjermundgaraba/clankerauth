import { Context, Effect, Schema, type Scope } from "effect";
import { type Headers as HttpHeaders, HttpServerRequest } from "effect/unstable/http";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { errors, Unauthorized } from "@clankerauth/admin-api";
import type { AdministrationResource } from "./administration-resource.ts";
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

/** A public error and the headers that refusal carries, such as an RFC 6750 challenge. */
interface Refusal {
  readonly error: (typeof errors)[number]["Type"];
  readonly headers: HttpHeaders.Input;
}

/**
 * MCP: the bearer access token for the administration resource, verified here. The
 * token's client must still exist and not be blocked; revocation of already-issued
 * access tokens takes effect at their expiry.
 */
export const bearerOwner = (service: Service, resource: AdministrationResource) => {
  const rejected = (): Refusal => ({
    error: new Unauthorized({ error: "Owner authorization required" }),
    headers: { "www-authenticate": resource.challenge(true) },
  });

  const failed = (cause: unknown): Refusal => ({ error: apiError(cause), headers: {} });

  return Authentication.middleware(
    CurrentOwner,
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const credential = request.headers.authorization !== undefined;

      const principal = yield* resource.verifier
        .verify(request.headers.authorization)
        .pipe(Effect.mapError((error) => resource.refuse(error, credential)));

      if (principal.actor.kind !== "client") return yield* Effect.fail(rejected());

      const rows = yield* service.sql`SELECT u.id, u.email FROM user u
      JOIN oauthClient c ON c.clientId = ${principal.actor.clientId}
      WHERE u.id = ${principal.subject} AND c.disabled IS NOT 1`.pipe(Effect.mapError(failed));

      if (!rows[0]) return yield* Effect.fail(rejected());

      const owner = yield* Schema.decodeUnknownEffect(OwnerRow)(rows[0]).pipe(
        Effect.mapError(failed),
      );

      return {
        userId: owner.id,
        email: owner.email,
        providerHeaders: providerSession(service, owner.id),
      };
    }).pipe(
      Effect.catch(({ error, headers }) =>
        Effect.flatMap(apiErrorResponse(error, headers), Effect.fail),
      ),
    ),
  );
};
