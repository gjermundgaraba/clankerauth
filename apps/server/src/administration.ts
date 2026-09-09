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
    if (!session || session.user.id !== service.owner())
      return yield* Effect.fail(new Unauthorized({ error: "Owner session required" }));
    if (mutate && headers.get("origin") !== settings.baseURL)
      return yield* Effect.fail(new Forbidden({ error: "Invalid origin" }));
    if (mutate && Date.now() - session.session.createdAt.getTime() > 15 * 60 * 1000)
      return yield* Effect.fail(
        new Forbidden({ error: "Sign out and sign in again before changing clients" }),
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
      return {
        clients: clients ?? [],
        resources: settings.resources,
        email,
        issuer: `${settings.baseURL}/api/auth`,
      };
    }),
    create: Effect.fn("Administration.create")(function* (
      headers: Headers,
      input: typeof ClientInput.Type,
    ) {
      const resource = settings.resources.find((r) => r.identifier === input.resource);
      if (!resource || !input.name.trim() || input.name.length > 100)
        return yield* Effect.fail(new BadRequest({ error: "Invalid client name or resource" }));
      return yield* Effect.tryPromise({
        try: async () => {
          const client = await auth.api.createOAuthClient({
            headers,
            body: {
              client_name: input.name.trim(),
              redirect_uris: [input.redirect],
              token_endpoint_auth_method: input.confidential ? "client_secret_basic" : "none",
              application_type: input.native ? "native" : "web",
              grant_types: ["authorization_code", "refresh_token"],
              scope: ["openid", "profile", "email", "offline_access", ...resource.scopes].join(" "),
            },
          });
          try {
            await auth.api.adminLinkClientResource({
              headers,
              params: { identifier: resource.identifier, client_id: client.client_id },
            });
          } catch (error) {
            await auth.api.deleteOAuthClient({ headers, body: { client_id: client.client_id } });
            throw error;
          }
          return client;
        },
        catch: apiError,
      });
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
