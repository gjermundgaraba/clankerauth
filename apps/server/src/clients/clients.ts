import {
  CurrentOwner,
  ClientNotFound,
} from "@gjermundgaraba/clankerauth-admin-api";
import type {
  ClientIsAutomatic,
  InternalServerError,
  ProviderRefused,
  ClientBlockInput,
  ClientCredentials,
  ClientId,
  ClientInput,
  ClientListResult,
  ClientRevokeInput,
  ClientUpdateInput,
  Client,
  Connection,
} from "@gjermundgaraba/clankerauth-admin-api";
import type * as Action from "@gjermundgaraba/effect-actions/Action";
import { Clock, Context, Effect, Layer, Redacted, Schema } from "effect";
import type { Scope } from "effect";

import {
  clearCodes,
  clearAuthorization,
  referencePrefix,
} from "../authorization/authorization.ts";
import { provider, refusal } from "../issuer/errors.ts";
import { Issuer } from "../issuer/issuer.ts";
import { Settings } from "../issuer/settings.ts";
import { Database, persisted } from "../platform/sqlite.ts";
import type { Sql } from "../platform/sqlite.ts";
import { protocolScopes, ResourceCatalog } from "../resources/catalog.ts";
import { Resources } from "../resources/resources.ts";
import { isAutomatic, requireManaged } from "./managed.ts";

const decodeConnections = persisted(
  Schema.Array(
    Schema.Struct({
      client_id: Schema.String,
      resource: Schema.String,
      scopes: Schema.fromJsonString(Schema.Array(Schema.String)),
      approvedAt: Schema.NullOr(Schema.DateTimeUtcFromString),
      refreshedAt: Schema.NullOr(Schema.DateTimeUtcFromString),
    })
  )
);

const ClientRow = Schema.Struct({
  clientId: Schema.String,
  name: Schema.NullOr(Schema.String),
  redirectUris: Schema.fromJsonString(Schema.Array(Schema.String)),
  tokenEndpointAuthMethod: Schema.NullOr(Schema.String),
  applicationType: Schema.NullOr(Schema.String),
  scopes: Schema.NullOr(Schema.fromJsonString(Schema.Array(Schema.String))),
  grantTypes: Schema.NullOr(Schema.fromJsonString(Schema.Array(Schema.String))),
  disabled: Schema.NullOr(Schema.Int),
  clientDiscoveryId: Schema.NullOr(Schema.String),
  userId: Schema.NullOr(Schema.String),
});

const decodeClients = persisted(Schema.Array(ClientRow));

const onboarding = (row: typeof ClientRow.Type) => {
  if (row.clientDiscoveryId !== null) {
    return "cimd" as const;
  }

  return isAutomatic(row) ? ("dcr" as const) : ("managed" as const);
};

interface SecretFields {
  readonly client_secret?: string | undefined;
  readonly client_secret_expires_at?: number | undefined;
}

const credentials = <Registered extends SecretFields>({
  client_secret,
  client_secret_expires_at,
  ...client
}: Registered) => ({
  ...client,
  ...(client_secret === undefined ? {} : { client_secret }),
  ...(client_secret_expires_at === undefined
    ? {}
    : { client_secret_expires_at }),
});

type Refusal = InternalServerError | ProviderRefused | Action.InvalidInput;

type Owned<A, E = never> = Effect.Effect<
  A,
  Refusal | E,
  CurrentOwner | Scope.Scope
>;

type Editing = ClientNotFound | ClientIsAutomatic;

export class Clients extends Context.Service<
  Clients,
  {
    readonly list: Effect.Effect<
      typeof ClientListResult.Type,
      InternalServerError,
      CurrentOwner
    >;
    readonly create: (
      input: typeof ClientInput.Type
    ) => Owned<typeof ClientCredentials.Type>;
    readonly update: (
      input: typeof ClientUpdateInput.Type
    ) => Owned<typeof Client.Type, Editing>;
    readonly rotate: (
      input: typeof ClientId.Type
    ) => Owned<typeof ClientCredentials.Type, Editing>;
    readonly connections: Effect.Effect<
      ReadonlyArray<typeof Connection.Type>,
      InternalServerError
    >;
    readonly revoke: (
      input: typeof ClientRevokeInput.Type
    ) => Effect.Effect<
      { revoked: boolean },
      InternalServerError | ClientNotFound
    >;
    readonly delete: (
      input: typeof ClientId.Type
    ) => Effect.Effect<
      { deleted: boolean },
      InternalServerError | ClientNotFound
    >;
    readonly block: (
      input: typeof ClientBlockInput.Type
    ) => Effect.Effect<
      { blocked: boolean },
      InternalServerError | ClientNotFound
    >;
  }
>()("clankerauth/Clients") {
  static readonly layer = Layer.effect(
    Clients,
    Effect.gen(function* () {
      const { sql, transaction } = yield* Database;
      const { auth } = yield* Issuer;
      const { baseURL } = yield* Settings;
      const catalog = yield* ResourceCatalog;
      const resources = yield* Resources;

      const exists = Effect.fn("Clients.exists")(function* (
        clientId: string,
        query: Sql
      ) {
        if (
          !(yield* query`SELECT 1 FROM oauthClient WHERE clientId = ${clientId}`)
            .length
        ) {
          return yield* ClientNotFound.of(clientId);
        }
      });

      const revoke = Effect.fn("Clients.revoke")(function* (
        clientId: string,
        resource: string | undefined,
        query: Sql
      ) {
        yield* exists(clientId, query);
        yield* clearAuthorization(query, { clientId, resource });

        return { revoked: true };
      });

      const connections = Effect.gen(function* () {
        const now = new Date(yield* Clock.currentTimeMillis).toISOString();

        const rows = yield* decodeConnections(
          yield* sql`WITH live AS (
              SELECT clientId, referenceId, scopes, createdAt FROM oauthRefreshToken
              WHERE revoked IS NULL AND expiresAt > ${now}
            ), held AS (
              SELECT clientId, referenceId FROM oauthConsent
              UNION SELECT clientId, referenceId FROM live
            )
            SELECT h.clientId AS client_id, r.identifier AS resource, c.updatedAt AS approvedAt,
              COALESCE(c.scopes, (SELECT l.scopes FROM live l WHERE l.clientId = h.clientId
                AND l.referenceId = h.referenceId ORDER BY l.createdAt DESC LIMIT 1)) AS scopes,
              (SELECT MAX(l.createdAt) FROM live l WHERE l.clientId = h.clientId
                AND l.referenceId = h.referenceId) AS refreshedAt
            FROM held h
            JOIN oauthResource r ON h.referenceId = ${referencePrefix} || r.identifier
            LEFT JOIN oauthConsent c ON c.clientId = h.clientId AND c.referenceId = h.referenceId
            ORDER BY client_id, resource`
        );

        return rows.map((row) => ({
          ...row,
          scopes: row.scopes.filter((scope) => !protocolScopes.includes(scope)),
        }));
      }).pipe(Effect.withSpan("Clients.connections"));

      return {
        connections,
        list: Effect.gen(function* () {
          const { email } = yield* CurrentOwner;

          const rows = yield* sql`
            SELECT clientId, name, redirectUris, tokenEndpointAuthMethod, applicationType, scopes,
              grantTypes, disabled, clientDiscoveryId, userId
            FROM oauthClient ORDER BY createdAt, clientId
          `;

          const clients = (yield* decodeClients(rows)).map((row) => ({
            client_id: row.clientId,
            onboarding: onboarding(row),
            blocked: row.disabled === 1,
            client_name: row.name ?? undefined,
            redirect_uris: row.redirectUris,
            token_endpoint_auth_method:
              row.tokenEndpointAuthMethod ?? undefined,
            application_type: row.applicationType,
            scope: row.scopes?.join(" "),
            grant_types: row.grantTypes ?? undefined,
          }));

          const listed = yield* Effect.all({
            resources: catalog.list,
            clientAccess: catalog.access,
            connections,
          });

          return {
            clients,
            resources: listed.resources,
            clientAccess: listed.clientAccess,
            connections: listed.connections,
            email,
            issuer: `${baseURL}/api/auth`,
          };
        }).pipe(Effect.withSpan("Clients.list")),
        create: Effect.fn("Clients.create")(function* (
          input: typeof ClientInput.Type
        ) {
          const { providerHeaders } = yield* CurrentOwner;

          const scopes = yield* catalog.scopesFor(input.resources);

          const headers = Redacted.value(yield* providerHeaders);

          const client = yield* provider(
            async () =>
              await auth.api.adminCreateOAuthClient({
                headers,
                body: {
                  client_name: input.client_name,
                  redirect_uris: [...input.redirect_uris],
                  token_endpoint_auth_method: input.token_endpoint_auth_method,
                  application_type: input.application_type,
                  grant_types: ["authorization_code", "refresh_token"],
                  scope: scopes.join(" "),
                  skip_consent: true,
                },
              }),
            { refused: refusal }
          );

          yield* resources.link(client.client_id, input.resources).pipe(
            Effect.tapError(() =>
              provider(async () => {
                await auth.api.deleteOAuthClient({
                  headers,
                  body: { client_id: client.client_id },
                });
              })
            )
          );

          return credentials(client);
        }),
        update: Effect.fn("Clients.update")(function* (
          input: typeof ClientUpdateInput.Type
        ) {
          yield* requireManaged(input.client_id, sql);
          const { providerHeaders } = yield* CurrentOwner;
          const headers = Redacted.value(yield* providerHeaders);

          return yield* provider(
            async () =>
              await auth.api.updateOAuthClient({
                headers,
                body: {
                  client_id: input.client_id,
                  update: {
                    client_name: input.client_name,
                    redirect_uris: [...input.redirect_uris],
                    application_type: input.application_type,
                  },
                },
              }),
            {
              refused: refusal,
              missing: () => ClientNotFound.of(input.client_id),
            }
          );
        }),
        rotate: Effect.fn("Clients.rotate")(function* (
          body: typeof ClientId.Type
        ) {
          yield* requireManaged(body.client_id, sql);
          const { providerHeaders } = yield* CurrentOwner;
          const headers = Redacted.value(yield* providerHeaders);

          const rotated = yield* provider(
            async () => await auth.api.rotateClientSecret({ headers, body }),
            {
              refused: refusal,
              missing: () => ClientNotFound.of(body.client_id),
            }
          );

          return credentials(rotated);
        }),
        revoke: ({ client_id, resource }) =>
          transaction((query) => revoke(client_id, resource, query)),
        delete: ({ client_id }) =>
          transaction((query) =>
            Effect.gen(function* () {
              yield* exists(client_id, query);
              yield* clearCodes(query, client_id, null);
              yield* query`DELETE FROM oauthClient WHERE clientId = ${client_id}`;

              return { deleted: true };
            })
          ),
        block: ({ client_id, blocked }) =>
          transaction((query) =>
            Effect.gen(function* () {
              yield* blocked
                ? revoke(client_id, undefined, query)
                : exists(client_id, query);

              yield* query`UPDATE oauthClient SET disabled = ${blocked ? 1 : 0}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${client_id}`;

              return { blocked };
            })
          ),
      };
    })
  );
}
