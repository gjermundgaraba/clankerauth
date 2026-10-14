import { Clock, Context, Effect, Layer, Schema, type Scope } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import {
  CurrentOwner,
  NotFound,
  type ClientAccessInput,
  type ClientAccessResult,
  type ClientBlockInput,
  type ClientCredentials,
  type ClientId,
  type ClientInput,
  type ClientListResult,
  type ClientRevokeInput,
  type ClientUpdateInput,
  type Client,
  type Connection,
  type OwnerError,
} from "@clankerauth/admin-api";
import { Database, persisted, type Sql } from "../platform/sqlite.ts";
import { provider } from "../issuer/errors.ts";
import { Issuer } from "../issuer/issuer.ts";
import { Settings } from "../issuer/settings.ts";
import { clearCodes, clearGrants, referencePrefix } from "../authorization/authorization.ts";
import { administrationIdentifier, protocolScopes, ResourceCatalog } from "../resources/catalog.ts";
import { Resources } from "../resources/resources.ts";

const decodeConnections = persisted(
  Schema.Array(
    Schema.Struct({
      client_id: Schema.String,
      resource: Schema.String,
      scopes: Schema.fromJsonString(Schema.Array(Schema.String)),
      approvedAt: Schema.NullOr(Schema.DateTimeUtcFromString),
      refreshedAt: Schema.NullOr(Schema.DateTimeUtcFromString),
    }),
  ),
);

const ClientRow = Schema.Struct({
  clientId: Schema.String,
  name: Schema.NullOr(Schema.String),
  redirectUris: Schema.fromJsonString(Schema.Array(Schema.String)),
  tokenEndpointAuthMethod: Schema.NullOr(Schema.String),
  applicationType: Schema.NullOr(Schema.String),
  scopes: Schema.NullOr(Schema.fromJsonString(Schema.Array(Schema.String))),
  grantTypes: Schema.NullOr(Schema.fromJsonString(Schema.Array(Schema.String))),
  disabled: Schema.NullOr(Schema.Number),
  clientDiscoveryId: Schema.NullOr(Schema.String),
  userId: Schema.NullOr(Schema.String),
});

const decodeClients = persisted(Schema.Array(ClientRow));

type Refusal = OwnerError | Action.InvalidInput;

type Owned<A> = Effect.Effect<A, Refusal, CurrentOwner | Scope.Scope>;

/**
 * Owner policy over provider client rows: blocking uses the provider's own `disabled`
 * flag, which it enforces at authorize, token and refresh.
 */
export class Clients extends Context.Service<
  Clients,
  {
    /** Clients, resources, managed clients' access and every client's connections. */
    readonly list: () => Effect.Effect<typeof ClientListResult.Type, OwnerError, CurrentOwner>;
    /** Registers a first-party client, linked to `resources`; its secret is returned once. */
    readonly create: (input: typeof ClientInput.Type) => Owned<typeof ClientCredentials.Type>;
    readonly update: (input: typeof ClientUpdateInput.Type) => Owned<typeof Client.Type>;
    readonly rotate: (input: typeof ClientId.Type) => Owned<typeof ClientCredentials.Type>;
    /**
     * What each client holds, per resource: a consent, a live refresh token, or both. A
     * managed client skips consent, so only its refresh tokens show. Scopes are the
     * consent's, else the newest token's; rotation revokes the replaced token.
     */
    readonly connections: () => Effect.Effect<ReadonlyArray<typeof Connection.Type>, OwnerError>;
    readonly setAccess: (
      input: typeof ClientAccessInput.Type,
    ) => Effect.Effect<typeof ClientAccessResult.Type, Refusal>;
    /** Without a resource, every authorization the client holds. */
    readonly revoke: (
      input: typeof ClientRevokeInput.Type,
    ) => Effect.Effect<{ revoked: boolean }, OwnerError>;
    /**
     * Forgets any client, managed or automatic; an automatic one can register again.
     * Its links, consents and tokens cascade with the row.
     */
    readonly delete: (
      input: typeof ClientId.Type,
    ) => Effect.Effect<{ deleted: boolean }, OwnerError>;
    readonly block: (
      input: typeof ClientBlockInput.Type,
    ) => Effect.Effect<{ blocked: boolean }, OwnerError>;
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

      const exists = Effect.fn("Clients.exists")(function* (clientId: string, query: Sql) {
        if (!(yield* query`SELECT 1 FROM oauthClient WHERE clientId = ${clientId}`).length)
          return yield* Effect.fail(new NotFound({ error: "Client not found" }));
      });

      const revoke = Effect.fn("Clients.revoke")(function* (
        clientId: string,
        resource: string | undefined,
        query: Sql,
      ) {
        yield* exists(clientId, query);
        yield* clearGrants(query, { clientId, resource });

        return { revoked: true };
      });

      /**
       * What each client holds, per resource: a consent, a live refresh token, or both. A
       * managed client skips consent, so only its refresh tokens show. Scopes are the
       * consent's, else the newest token's; rotation revokes the replaced token.
       */
      const connections = Effect.fn("Clients.connections")(function* () {
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
            ORDER BY client_id, resource`,
        );

        return rows.map((row) => ({
          ...row,
          scopes: row.scopes.filter((scope) => !protocolScopes.includes(scope)),
        }));
      });

      return {
        connections,
        list: Effect.fn("Administration.list")(function* () {
          const { email } = yield* CurrentOwner;

          const rows = yield* sql`
            SELECT clientId, name, redirectUris, tokenEndpointAuthMethod, applicationType, scopes,
              grantTypes, disabled, clientDiscoveryId, userId
            FROM oauthClient ORDER BY createdAt, clientId
          `;

          const clients = (yield* decodeClients(rows)).map((row) => ({
            client_id: row.clientId,
            onboarding:
              row.clientDiscoveryId !== null
                ? ("cimd" as const)
                : row.userId === null
                  ? ("dcr" as const)
                  : ("managed" as const),
            blocked: row.disabled === 1,
            client_name: row.name ?? undefined,
            redirect_uris: row.redirectUris,
            token_endpoint_auth_method: row.tokenEndpointAuthMethod ?? undefined,
            application_type: row.applicationType,
            scope: row.scopes?.join(" "),
            grant_types: row.grantTypes ?? undefined,
          }));

          const listed = yield* Effect.all({
            resources: catalog.list(),
            clientAccess: catalog.access(),
            connections: connections(),
          });

          return {
            clients,
            resources: listed.resources.map((resource) => ({
              ...resource,
              builtIn: resource.identifier === administrationIdentifier(baseURL),
            })),
            clientAccess: listed.clientAccess,
            connections: listed.connections,
            email,
            issuer: `${baseURL}/api/auth`,
          };
        }),
        create: Effect.fn("Administration.create")(function* (input: typeof ClientInput.Type) {
          const { providerHeaders } = yield* CurrentOwner;

          const scopes = yield* catalog.scopesFor(input.resources);

          const headers = yield* providerHeaders;

          const client = yield* provider(() =>
            // The administrative endpoint accepts skip_consent; the plain one drops it.
            auth.api.adminCreateOAuthClient({
              headers,
              body: {
                client_name: input.client_name,
                redirect_uris: [...input.redirect_uris],
                token_endpoint_auth_method: input.token_endpoint_auth_method,
                application_type: input.application_type,
                grant_types: ["authorization_code", "refresh_token"],
                scope: scopes.join(" "),
                // Owner-registered clients are first party: no consent screen.
                skip_consent: true,
              },
            }),
          );

          yield* resources
            .setAccess({ client_id: client.client_id, resources: input.resources })
            .pipe(
              Effect.tapError(() =>
                provider(() =>
                  auth.api.deleteOAuthClient({ headers, body: { client_id: client.client_id } }),
                ),
              ),
            );

          return client;
        }),
        update: Effect.fn("Administration.update")(function* (
          input: typeof ClientUpdateInput.Type,
        ) {
          const { providerHeaders } = yield* CurrentOwner;
          const headers = yield* providerHeaders;

          return yield* provider(() =>
            auth.api.updateOAuthClient({
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
          );
        }),
        rotate: Effect.fn("Administration.rotate")(function* (body: typeof ClientId.Type) {
          const { providerHeaders } = yield* CurrentOwner;
          const headers = yield* providerHeaders;

          return yield* provider(() => auth.api.rotateClientSecret({ headers, body }));
        }),
        setAccess: Effect.fn("Clients.setAccess")(function* (input: typeof ClientAccessInput.Type) {
          return { clientAccess: yield* resources.setAccess(input) };
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
            }),
          ),
        block: ({ client_id, blocked }) =>
          transaction((query) =>
            Effect.gen(function* () {
              if (blocked) yield* revoke(client_id, undefined, query);
              else yield* exists(client_id, query);
              yield* query`UPDATE oauthClient SET disabled = ${blocked ? 1 : 0}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${client_id}`;

              return { blocked };
            }),
          ),
      };
    }),
  );
}
