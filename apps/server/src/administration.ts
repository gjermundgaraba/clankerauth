import { Effect, Schema } from "effect";
import { apiError, provider } from "./api-errors.ts";
import {
  BadRequest,
  type ClientInput,
  type ClientBlockInput,
  type ClientId,
  type ClientAccessInput,
  type Resource,
  type ResourceId,
  type SetupInput,
} from "@clankerauth/api";
import { mcpResource } from "./resources.ts";
import { CurrentOwner } from "./current-owner.ts";
import { createOwner, type Service } from "./auth.ts";

export function administration(service: Service) {
  const { auth, settings } = service;

  return {
    setup: Effect.fn("Administration.setup")(function* (input: typeof SetupInput.Type) {
      yield* createOwner(service, input).pipe(Effect.mapError(apiError));

      return { created: true };
    }),
    list: Effect.fn("Administration.list")(function* () {
      const { providerHeaders, email } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      const managed = yield* provider(() => auth.api.getOAuthClients({ headers }));

      const rows = yield* service.sql`
        SELECT p.clientId AS client_id, p.source AS onboarding, p.blocked,
          c.name, c.tokenEndpointAuthMethod, c.scopes, c.grantTypes,
          CASE WHEN c.clientId IS NULL THEN '[]' ELSE c.redirectUris END AS redirectUris
        FROM clientOnboarding p LEFT JOIN oauthClient c ON c.clientId = p.clientId
      `.pipe(Effect.mapError(apiError));

      const automatic = (yield* Schema.decodeUnknownEffect(
        Schema.Array(
          Schema.Struct({
            client_id: Schema.String,
            onboarding: Schema.Literals(["dcr", "cimd"]),
            blocked: Schema.Number,
            name: Schema.NullOr(Schema.String),
            redirectUris: Schema.fromJsonString(Schema.Array(Schema.String)),
            tokenEndpointAuthMethod: Schema.NullOr(Schema.String),
            scopes: Schema.NullOr(Schema.fromJsonString(Schema.Array(Schema.String))),
            grantTypes: Schema.NullOr(Schema.fromJsonString(Schema.Array(Schema.String))),
          }),
        ),
      )(rows).pipe(Effect.mapError(apiError))).map((row) => ({
        client_id: row.client_id,
        onboarding: row.onboarding,
        blocked: row.blocked !== 0,
        client_name: row.name ?? undefined,
        redirect_uris: row.redirectUris,
        token_endpoint_auth_method: row.tokenEndpointAuthMethod ?? undefined,
        scope: row.scopes?.join(" "),
        grant_types: row.grantTypes ?? undefined,
      }));

      const automaticIds = new Set(automatic.map((client) => client.client_id));

      const clients = [
        ...(managed ?? [])
          .filter((client) => !automaticIds.has(client.client_id))
          .map((client) => ({
            ...client,
            onboarding: "managed" as const,
            blocked: client.disabled === true,
          })),
        ...automatic,
      ];

      const catalog = yield* Effect.all({
        resources: service.resources.list(),
        clientAccess: service.resources.access(),
      }).pipe(Effect.mapError(apiError));

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

      if (!input.name.trim() || input.name.length > 100)
        return yield* Effect.fail(
          new BadRequest({ error: "Client names require 1–100 characters" }),
        );

      const scopes = yield* service.resources
        .scopesFor(input.resources)
        .pipe(Effect.mapError(apiError));

      const headers = yield* providerHeaders;

      const client = yield* provider(() =>
        // The administrative endpoint accepts skip_consent; the plain one drops it.
        auth.api.adminCreateOAuthClient({
          headers,
          body: {
            client_name: input.name.trim(),
            redirect_uris: [input.redirect],
            token_endpoint_auth_method: input.confidential ? "client_secret_basic" : "none",
            application_type: input.native ? "native" : "web",
            grant_types: ["authorization_code", "refresh_token"],
            scope: scopes.join(" "),
            // Owner-registered clients are first party: no consent screen.
            skip_consent: true,
          },
        }),
      );

      yield* service.resources.setAccess(client.client_id, input.resources, headers).pipe(
        Effect.mapError(apiError),
        Effect.tapError(() =>
          provider(() =>
            auth.api.deleteOAuthClient({ headers, body: { client_id: client.client_id } }),
          ),
        ),
      );

      return client;
    }),
    access: Effect.fn("Administration.access")(function* (input: typeof ClientAccessInput.Type) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      const clientAccess = yield* service.resources
        .setAccess(input.client_id, input.resources, headers)
        .pipe(Effect.mapError(apiError));

      return { clientAccess };
    }),
    createResource: Effect.fn("Administration.createResource")(function* (
      input: typeof Resource.Type,
    ) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      return yield* service.resources.create(input, headers).pipe(Effect.mapError(apiError));
    }),
    updateResource: Effect.fn("Administration.updateResource")(function* (
      input: typeof Resource.Type,
    ) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      return yield* service.resources.update(input, headers).pipe(Effect.mapError(apiError));
    }),
    deleteResource: Effect.fn("Administration.deleteResource")(function* (
      input: typeof ResourceId.Type,
    ) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      return yield* service.resources
        .delete(input.identifier, headers)
        .pipe(Effect.mapError(apiError));
    }),
    delete: Effect.fn("Administration.delete")(function* (body: typeof ClientId.Type) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;
      yield* provider(() => auth.api.deleteOAuthClient({ headers, body }));

      return { deleted: true };
    }),
    revoke: Effect.fn("Administration.revoke")(function* (input: typeof ClientId.Type) {
      yield* CurrentOwner;

      return yield* service.onboarding.revoke(input.client_id).pipe(Effect.mapError(apiError));
    }),
    block: Effect.fn("Administration.block")(function* (input: typeof ClientBlockInput.Type) {
      yield* CurrentOwner;

      return yield* service.onboarding
        .block(input.client_id, input.blocked)
        .pipe(Effect.mapError(apiError));
    }),
    rotate: Effect.fn("Administration.rotate")(function* (body: typeof ClientId.Type) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      return yield* provider(() => auth.api.rotateClientSecret({ headers, body }));
    }),
  };
}
