import { Clock, Effect, Redacted, Schema } from "effect";
import { HttpServerRequest } from "effect/http";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import * as KeyList from "@gjermundgaraba/clankerauth-sdk/key-list";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import {
  administrationScopes,
  CurrentOwner,
  KeyPermissions,
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

const decodeKeyRow = persisted(
  Schema.Struct({
    id: Schema.String,
    email: Schema.String,
    permissions: Schema.NullOr(Schema.fromJsonString(KeyPermissions)),
  }),
);

export const bearerOwner = (resource: AdministrationResource) =>
  Authentication.layer(
    OwnerToken,
    Effect.gen(function* () {
      const { sql } = yield* Database;
      const owner = yield* OwnerAccount;
      const identifier = resource.protectedResource.resource;

      const rejected = () =>
        new Action.Unauthenticated({ message: "Owner authorization required" });

      // why: read on every request, so disabling, deleting or re-scoping a key applies to the next one
      const keyOwner = Effect.fnUntraced(function* (key: string) {
        const digest = Buffer.from(yield* Effect.promise(() => KeyList.digest(key))).toString(
          "base64url",
        );

        const now = new Date(yield* Clock.currentTimeMillis).toISOString();

        const rows = yield* sql`SELECT u.id, u.email, k.permissions FROM apikey k
      JOIN user u ON u.id = k.referenceId
      WHERE k.key = ${digest} AND k.enabled = 1 AND (k.expiresAt IS NULL OR k.expiresAt > ${now})`;

        if (!rows[0]) return yield* rejected();

        const row = yield* decodeKeyRow(rows[0]);
        const scopes = row.permissions?.[identifier] ?? [];

        if (
          !scopes.includes(administrationScopes.read) &&
          !scopes.includes(administrationScopes.write)
        )
          return yield* rejected();

        return owner.caller(row.id, row.email, scopes.includes(administrationScopes.write));
      });

      const clientOwner = Effect.fnUntraced(function* (token: Redacted.Redacted<string>) {
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

      return (token: Redacted.Redacted<string>) =>
        Redacted.value(token).startsWith(KeyList.keyPrefix)
          ? keyOwner(Redacted.value(token))
          : clientOwner(token);
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
