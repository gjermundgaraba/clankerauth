import { Effect, Schema } from "effect";
import type { Redacted } from "effect";
import { HttpServerRequest } from "effect/http";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import {
  administrationScopes,
  CurrentOwner,
  OwnerToken,
  ServiceUnavailable,
} from "@gjermundgaraba/clankerauth-admin-api";
import type { OwnerSession } from "@gjermundgaraba/clankerauth-admin-api";
import type { AdministrationResource } from "./administration-resource.ts";
import { provider, unavailability } from "../issuer/errors.ts";
import { Database, persisted } from "../platform/sqlite.ts";
import { OwnerAccount } from "./owner.ts";
import { Issuer } from "../issuer/issuer.ts";

export const sessionOwner = (authentication: typeof OwnerSession) =>
  Authentication.layer(
    authentication,
    Effect.map(
      Issuer,
      (issuer) => () =>
        Effect.gen(function* () {
          const request = yield* HttpServerRequest.HttpServerRequest;
          const headers = new Headers(request.headers);

          const session = yield* provider(() => issuer.auth.api.getSession({ headers }), {
            unavailable: unavailability,
          });

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

export const bearerOwner = (resource: AdministrationResource) =>
  Authentication.layer(
    OwnerToken,
    Effect.gen(function* () {
      const { sql } = yield* Database;
      const owner = yield* OwnerAccount;

      const rejected = () =>
        new Action.Unauthenticated({ message: "Owner authorization required" });

      return (token: Redacted.Redacted<string>) =>
        Effect.gen(function* () {
          const principal = yield* Resource.authenticate(resource.verifier, token).pipe(
            Effect.catchTag("ProviderUnavailable", () =>
              Effect.fail(new ServiceUnavailable({ message: "Request could not be completed" })),
            ),
          );

          if (principal.actor.kind !== "client") return yield* rejected();
          const writable = principal.scopes.includes(administrationScopes.write);

          if (!writable && !principal.scopes.includes(administrationScopes.read))
            return yield* new Action.Forbidden({
              message: "Insufficient scope",
              scopes: [administrationScopes.read],
            });

          const rows = yield* sql`SELECT u.id, u.email FROM user u
      JOIN oauthClient c ON c.clientId = ${principal.actor.clientId}
      WHERE u.id = ${principal.subject} AND c.disabled IS NOT 1`;

          if (!rows[0]) return yield* rejected();

          const row = yield* decodeOwnerRow(rows[0]);

          return owner.caller(row.id, row.email, writable);
        });
    }),
    { protectedResource: resource.protectedResource },
  );

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
