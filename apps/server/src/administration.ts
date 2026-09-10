import { Effect, Schema } from "effect";
import { APIError } from "better-auth/api";
import {
  BadRequest,
  Conflict,
  Forbidden,
  InternalServerError,
  NotFound,
  ServiceUnavailable,
  TooManyRequests,
  Unauthorized,
  type ClientInput,
  type ClientBlockInput,
  type ClientId,
  type ClientAccessInput,
  type Resource,
  type ResourceId,
  type SetupInput,
} from "@clankerauth/api";
import { createOwner, type Service } from "./auth.ts";

function apiError(error: unknown) {
  const body = { error: "Request could not be completed" };
  if (error instanceof APIError) {
    switch (error.statusCode) {
      case 400:
        return new BadRequest(body);
      case 401:
        return new Unauthorized({ error: "Authentication required" });
      case 403:
        return new Forbidden(body);
      case 404:
        return new NotFound(body);
      case 409:
        return new Conflict(body);
      case 429:
        return new TooManyRequests(body);
      case 503:
        return new ServiceUnavailable(body);
    }
  }
  return new InternalServerError(body);
}

// Local and provider errors share status mapping; provider-only descriptions stay private.
function resourceError(error: unknown) {
  if (error instanceof APIError) {
    const body = { error: error.body?.message ?? "Resource request could not be completed" };
    if (error.statusCode === 400) return new BadRequest(body);
    if (error.statusCode === 404) return new NotFound(body);
    if (error.statusCode === 409) return new Conflict(body);
  }
  return new InternalServerError({ error: "Request could not be completed" });
}

export function administration(service: Service) {
  const { auth, settings } = service;
  const requireOwner = Effect.fn("Administration.requireOwner")(function* (
    headers: Headers,
    mutate: boolean,
  ) {
    const session = yield* Effect.tryPromise({
      try: () => auth.api.getSession({ headers }),
      catch: apiError,
    });
    if (!session) return yield* Effect.fail(new Unauthorized({ error: "Owner session required" }));
    if (mutate && headers.get("origin") !== settings.baseURL)
      return yield* Effect.fail(new Forbidden({ error: "Invalid origin" }));
    return session;
  });
  return {
    requireOwner,
    setup: Effect.fn("Administration.setup")(function* (input: typeof SetupInput.Type) {
      yield* Effect.tryPromise({ try: () => createOwner(service, input), catch: apiError });
      return { created: true };
    }),
    list: Effect.fn("Administration.list")(function* (headers: Headers, email: string) {
      const managed = yield* Effect.tryPromise({
        try: () => auth.api.getOAuthClients({ headers }),
        catch: apiError,
      });
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
      }).pipe(Effect.mapError(resourceError));
      return {
        clients,
        ...catalog,
        email,
        issuer: `${settings.baseURL}/api/auth`,
      };
    }),
    create: Effect.fn("Administration.create")(function* (
      headers: Headers,
      input: typeof ClientInput.Type,
    ) {
      if (!input.name.trim() || input.name.length > 100)
        return yield* Effect.fail(
          new BadRequest({ error: "Client names require 1–100 characters" }),
        );
      const scopes = yield* service.resources
        .scopesFor(input.resources)
        .pipe(Effect.mapError(resourceError));
      const client = yield* Effect.tryPromise({
        try: () =>
          auth.api.createOAuthClient({
            headers,
            body: {
              client_name: input.name.trim(),
              redirect_uris: [input.redirect],
              token_endpoint_auth_method: input.confidential ? "client_secret_basic" : "none",
              application_type: input.native ? "native" : "web",
              grant_types: ["authorization_code", "refresh_token"],
              scope: scopes.join(" "),
            },
          }),
        catch: apiError,
      });
      yield* service.resources.setAccess(client.client_id, input.resources, headers).pipe(
        Effect.mapError(resourceError),
        Effect.tapError(() =>
          Effect.tryPromise({
            try: () =>
              auth.api.deleteOAuthClient({ headers, body: { client_id: client.client_id } }),
            catch: apiError,
          }),
        ),
      );
      return client;
    }),
    access: Effect.fn("Administration.access")(function* (
      headers: Headers,
      input: typeof ClientAccessInput.Type,
    ) {
      const clientAccess = yield* service.resources
        .setAccess(input.client_id, input.resources, headers)
        .pipe(Effect.mapError(resourceError));
      return { clientAccess };
    }),
    createResource: Effect.fn("Administration.createResource")(function* (
      headers: Headers,
      input: typeof Resource.Type,
    ) {
      return yield* service.resources.create(input, headers).pipe(Effect.mapError(resourceError));
    }),
    updateResource: Effect.fn("Administration.updateResource")(function* (
      headers: Headers,
      input: typeof Resource.Type,
    ) {
      return yield* service.resources.update(input, headers).pipe(Effect.mapError(resourceError));
    }),
    deleteResource: Effect.fn("Administration.deleteResource")(function* (
      headers: Headers,
      input: typeof ResourceId.Type,
    ) {
      return yield* service.resources
        .delete(input.identifier, headers)
        .pipe(Effect.mapError(resourceError));
    }),
    delete: Effect.fn("Administration.delete")(function* (
      headers: Headers,
      body: typeof ClientId.Type,
    ) {
      yield* Effect.tryPromise({
        try: () => auth.api.deleteOAuthClient({ headers, body }),
        catch: apiError,
      });
      return { deleted: true };
    }),
    revoke: Effect.fn("Administration.revoke")(function* (input: typeof ClientId.Type) {
      return yield* service.onboarding.revoke(input.client_id).pipe(Effect.mapError(resourceError));
    }),
    block: Effect.fn("Administration.block")(function* (input: typeof ClientBlockInput.Type) {
      return yield* service.onboarding
        .block(input.client_id, input.blocked)
        .pipe(Effect.mapError(resourceError));
    }),
    rotate: Effect.fn("Administration.rotate")(function* (
      headers: Headers,
      body: typeof ClientId.Type,
    ) {
      return yield* Effect.tryPromise({
        try: () => auth.api.rotateClientSecret({ headers, body }),
        catch: apiError,
      });
    }),
  };
}
