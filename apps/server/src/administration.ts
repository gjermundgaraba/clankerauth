import { Effect, Schema } from "effect";
import { provider } from "./api-errors.ts";
import type {
  ClientInput,
  ClientUpdateInput,
  ClientBlockInput,
  ClientId,
  ClientAccessInput,
  Resource,
  ResourceId,
  SetupInput,
} from "@clankerauth/admin-api";
import { persisted } from "./database.ts";
import { mcpResource } from "./resources.ts";
import { CurrentOwner } from "./current-owner.ts";
import { ResponseCookies } from "./response-cookies.ts";
import { Auth, createOwner } from "./auth.ts";

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

export const administration = Effect.map(Auth, (service) => {
  const { auth, settings } = service;

  return {
    setup: Effect.fn("Administration.setup")(function* (input: typeof SetupInput.Type) {
      const cookies = yield* createOwner(service, input);

      yield* (yield* ResponseCookies).add(cookies);

      return { created: true };
    }),
    // The provider lists only the session owner's clients; automatic clients have no owner.
    list: Effect.fn("Administration.list")(function* () {
      const { email } = yield* CurrentOwner;

      const rows = yield* service.sql`
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

      const catalog = yield* Effect.all({
        resources: service.resources.list(),
        clientAccess: service.resources.access(),
      });

      return {
        clients,
        resources: catalog.resources.map((resource) => ({
          ...resource,
          builtIn: resource.identifier === mcpResource(settings.baseURL),
        })),
        clientAccess: catalog.clientAccess,
        email,
        issuer: `${settings.baseURL}/api/auth`,
      };
    }),
    create: Effect.fn("Administration.create")(function* (input: typeof ClientInput.Type) {
      const { providerHeaders } = yield* CurrentOwner;

      const scopes = yield* service.resources.scopesFor(input.resources);

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

      yield* service.resources
        .setAccess(client.client_id, input.resources, headers)
        .pipe(
          Effect.tapError(() =>
            provider(() =>
              auth.api.deleteOAuthClient({ headers, body: { client_id: client.client_id } }),
            ),
          ),
        );

      return client;
    }),
    update: Effect.fn("Administration.update")(function* (input: typeof ClientUpdateInput.Type) {
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
    access: Effect.fn("Administration.access")(function* (input: typeof ClientAccessInput.Type) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      const clientAccess = yield* service.resources.setAccess(
        input.client_id,
        input.resources,
        headers,
      );

      return { clientAccess };
    }),
    createResource: Effect.fn("Administration.createResource")(function* (
      input: typeof Resource.Type,
    ) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      return yield* service.resources.create(input, headers);
    }),
    updateResource: Effect.fn("Administration.updateResource")(function* (
      input: typeof Resource.Type,
    ) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      return yield* service.resources.update(input, headers);
    }),
    deleteResource: Effect.fn("Administration.deleteResource")(function* (
      input: typeof ResourceId.Type,
    ) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      return yield* service.resources.delete(input.identifier, headers);
    }),
    delete: Effect.fn("Administration.delete")(function* (body: typeof ClientId.Type) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;
      yield* provider(() => auth.api.deleteOAuthClient({ headers, body }));

      return { deleted: true };
    }),
    revoke: Effect.fn("Administration.revoke")(function* (input: typeof ClientId.Type) {
      yield* CurrentOwner;

      return yield* service.clients.revoke(input.client_id);
    }),
    block: Effect.fn("Administration.block")(function* (input: typeof ClientBlockInput.Type) {
      yield* CurrentOwner;

      return yield* service.clients.block(input.client_id, input.blocked);
    }),
    rotate: Effect.fn("Administration.rotate")(function* (body: typeof ClientId.Type) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      return yield* provider(() => auth.api.rotateClientSecret({ headers, body }));
    }),
  };
});
