import { Effect, Schema } from "effect";
import type { Redacted } from "effect";
import { HttpServerRequest } from "effect/http";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import { CurrentOwner, OwnerToken, ServiceUnavailable } from "@clankerauth/admin-api";
import type { OwnerSession } from "@clankerauth/admin-api";
import type { AdministrationResource } from "./administration-resource.ts";
import { provider } from "./api-errors.ts";
import { persisted } from "./database.ts";
import { providerSession } from "./provider-session.ts";
import { administrationScopes } from "./resources.ts";
import { Auth } from "./auth.ts";

/**
 * Dashboard HTTP: the owner session's provider, the issuer's SameSite session cookie, which
 * authentication requires before this runs, named as the deployment's sessions name it:
 * `authentication` is `ownerSession` of that name. Better Auth reads and checks the session from
 * the request's cookies; a failure of its own is one of the errors the descriptor declares.
 */
export const sessionOwner = (authentication: typeof OwnerSession) =>
  Authentication.layer(
    authentication,
    Effect.map(
      Auth,
      (service) => () =>
        Effect.gen(function* () {
          const request = yield* HttpServerRequest.HttpServerRequest;
          const headers = new Headers(request.headers);

          const session = yield* provider(() => service.auth.api.getSession({ headers }));

          if (!session)
            return yield* new Action.Unauthenticated({ message: "Owner session required" });

          return {
            providerHeaders: Effect.succeed(headers),
            userId: session.user.id,
            email: session.user.email,
            writable: true,
          };
        }),
    ),
  );

const decodeOwnerRow = persisted(Schema.Struct({ id: Schema.String, email: Schema.String }));

/**
 * MCP: `OwnerToken`'s provider, the bearer access token for the administration resource,
 * verified here; it publishes the resource's discovery. The token's client must still exist
 * and not be blocked; revocation of already-issued access tokens takes effect at their expiry.
 */
export const bearerOwner = (resource: AdministrationResource) =>
  Authentication.layer(
    OwnerToken,
    Effect.map(Auth, (service) => {
      /** The token was accepted, its owner or client was not: a 401 naming `invalid_token`. */
      const rejected = () =>
        new Action.Unauthenticated({ message: "Owner authorization required" });

      return (token: Redacted.Redacted<string>) =>
        Effect.gen(function* () {
          // The issuer is this process, so its own vocabulary answers it being unreachable.
          const principal = yield* Resource.authenticate(resource.verifier, token).pipe(
            Effect.catchTag("ProviderUnavailable", () =>
              Effect.fail(new ServiceUnavailable({ error: "Request could not be completed" })),
            ),
          );

          // The administration resource takes no API keys (`apiKeys: false`), so every
          // principal is a client's: this never refuses, it narrows the actor's type.
          if (principal.actor.kind !== "client") return yield* rejected();
          // Write allows everything, read allows listing, and a token with neither is refused
          // here with a challenge; the authorizer requires write for changes.
          const writable = principal.scopes.includes(administrationScopes.write);

          if (!writable && !principal.scopes.includes(administrationScopes.read))
            return yield* new Action.Forbidden({
              message: "Insufficient scope",
              scopes: [administrationScopes.read],
            });

          const rows = yield* service.sql`SELECT u.id, u.email FROM user u
      JOIN oauthClient c ON c.clientId = ${principal.actor.clientId}
      WHERE u.id = ${principal.subject} AND c.disabled IS NOT 1`;

          if (!rows[0]) return yield* rejected();

          const owner = yield* decodeOwnerRow(rows[0]);

          return {
            userId: owner.id,
            email: owner.email,
            writable,
            providerHeaders: providerSession(service, owner.id),
          };
        });
    }),
    { protectedResource: resource.protectedResource },
  );

/**
 * The authorizer of owner administration, on every surface: a read needs no more than the
 * authentication admitted, and a change needs a caller that may write. The dashboard
 * session always may; a read-only token steps up for the write scope.
 */
export const authorizeOwner = (action: Action.Any) =>
  action.readOnly
    ? Effect.void
    : Effect.flatMap(CurrentOwner, ({ writable }) =>
        writable
          ? Effect.void
          : Effect.fail(
              new Action.Forbidden({
                message: `This action requires the ${administrationScopes.write} scope`,
                scopes: [administrationScopes.write],
              }),
            ),
      );
