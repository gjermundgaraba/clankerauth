import { Effect } from "effect";
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

// Only the local Resource store supplies these user-facing domain errors.
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
    const owner = yield* service.owner().pipe(Effect.mapError(apiError));
    if (!session || session.user.id !== owner)
      return yield* Effect.fail(new Unauthorized({ error: "Owner session required" }));
    if (mutate && headers.get("origin") !== settings.baseURL)
      return yield* Effect.fail(new Forbidden({ error: "Invalid origin" }));
    if (mutate && Date.now() - session.session.createdAt.getTime() > 15 * 60 * 1000)
      return yield* Effect.fail(
        new Forbidden({ error: "Sign out and sign in again before changing Clients or Resources" }),
      );
    return session;
  });
  return {
    requireOwner,
    setup: Effect.fn("Administration.setup")(function* (input: typeof SetupInput.Type) {
      yield* Effect.tryPromise({ try: () => createOwner(service, input), catch: apiError });
      return { created: true };
    }),
    list: Effect.fn("Administration.list")(function* (headers: Headers, email: string) {
      const clients = yield* Effect.tryPromise({
        try: () => auth.api.getOAuthClients({ headers }),
        catch: apiError,
      });
      const catalog = yield* Effect.all({
        resources: service.resources.list(),
        clientAccess: service.resources.access(),
      }).pipe(Effect.mapError(resourceError));
      return {
        clients: clients ?? [],
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
      if (!input.resources.length)
        return yield* Effect.fail(new BadRequest({ error: "Choose unique Resources" }));
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
      yield* service.resources.setAccess(client.client_id, input.resources).pipe(
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
    access: Effect.fn("Administration.access")(function* (input: typeof ClientAccessInput.Type) {
      const clientAccess = yield* service.resources
        .setAccess(input.client_id, input.resources)
        .pipe(Effect.mapError(resourceError));
      return { clientAccess };
    }),
    createResource: Effect.fn("Administration.createResource")(function* (
      input: typeof Resource.Type,
    ) {
      return yield* service.resources.create(input).pipe(Effect.mapError(resourceError));
    }),
    updateResource: Effect.fn("Administration.updateResource")(function* (
      input: typeof Resource.Type,
    ) {
      return yield* service.resources.update(input).pipe(Effect.mapError(resourceError));
    }),
    deleteResource: Effect.fn("Administration.deleteResource")(function* (
      input: typeof ResourceId.Type,
    ) {
      return yield* service.resources.delete(input.identifier).pipe(Effect.mapError(resourceError));
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
