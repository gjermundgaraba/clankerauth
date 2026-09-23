import { Context, Effect, Schema, type Scope } from "effect";
import { type Headers as HttpHeaders, HttpServerRequest } from "effect/unstable/http";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { Unauthorized } from "@clankerauth/admin-api";
import type { AdministrationResource } from "./administration-resource.ts";
import { apiErrorResponse, provider, type ApiError } from "./api-errors.ts";
import { persisted } from "./database.ts";
import { providerSession } from "./provider-session.ts";
import { Auth } from "./auth.ts";

/** Authenticated per request, never supplied by action arguments or at startup. */
export class CurrentOwner extends Context.Service<
  CurrentOwner,
  {
    readonly userId: string;
    readonly email: string;
    readonly providerHeaders: Effect.Effect<Headers, ApiError, Scope.Scope>;
  }
>()("clankerauth/CurrentOwner") {}

const fail = (error: ApiError) => Effect.flatMap(apiErrorResponse(error), Effect.fail);

/** Dashboard HTTP: the issuer's SameSite session cookie. */
export const sessionOwner = Effect.map(Auth, (service) =>
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
  ),
);

/** A public error and the headers that refusal carries, such as an RFC 6750 challenge. */
interface Refusal {
  readonly error: ApiError;
  readonly headers: HttpHeaders.Input;
}

const decodeOwnerRow = persisted(Schema.Struct({ id: Schema.String, email: Schema.String }));

/**
 * MCP: the bearer access token for the administration resource, verified here. The
 * token's client must still exist and not be blocked; revocation of already-issued
 * access tokens takes effect at their expiry.
 */
export const bearerOwner = Effect.fnUntraced(function* (resource: AdministrationResource) {
  const service = yield* Auth;

  const rejected = (): Refusal => ({
    error: new Unauthorized({ error: "Owner authorization required" }),
    headers: { "www-authenticate": resource.challenge(true) },
  });

  const failed = (error: ApiError): Refusal => ({ error, headers: {} });

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

      const owner = yield* decodeOwnerRow(rows[0]).pipe(Effect.mapError(failed));

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
});
