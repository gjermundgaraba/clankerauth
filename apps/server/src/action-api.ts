import { Effect, Layer, Match } from "effect";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import { McpProtocol } from "effect/unstable/ai";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import { OpenApi } from "effect/unstable/httpapi";
import {
  Http,
  Administration,
  IssuerActions,
  Forbidden,
  InternalServerError,
} from "@clankerauth/api";
import { apiErrorResponse } from "./api-errors.ts";
import { administration } from "./administration.ts";
import { machineKeys } from "./machine-keys.ts";
import { CurrentOwner, ownerAuthentication } from "./current-owner.ts";
import { mcpAuthentication } from "./mcp-auth.ts";
import { mcpResource, mcpScope } from "./resources.ts";
import type { Service } from "./auth.ts";

export function actionRoutes(service: Service, mcpAllowedOrigins: readonly string[]) {
  const admin = administration(service);
  const keys = machineKeys(service);

  const owner = Administration.implement({
    listClients: admin.list,
    createClient: admin.create,
    deleteClient: admin.delete,
    revokeClient: admin.revoke,
    blockClient: admin.block,
    rotateClientSecret: admin.rotate,
    setClientAccess: admin.access,
    createResource: admin.createResource,
    updateResource: admin.updateResource,
    deleteResource: admin.deleteResource,
    listApiKeys: keys.list,
    createApiKey: keys.create,
    updateApiKey: keys.update,
    deleteApiKey: keys.delete,
  });

  const issuer = IssuerActions.implement({
    setupStatus: () =>
      service.owner().pipe(
        Effect.map((owner) => ({ required: !owner })),
        Effect.mapError(() => new InternalServerError({ error: "Request could not be completed" })),
      ),
    setupOwner: (input) =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;

        if (request.headers.origin !== service.settings.baseURL)
          return yield* Effect.fail(new Forbidden({ error: "Invalid origin" }));

        return yield* admin.setup(input);
      }),
    verifyApiKey: ({ resource }) =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;

        return yield* keys.verify(new Headers(request.headers), resource);
      }),
  });

  const discovery = Authentication.protectedResource({
    resource: mcpResource(service.settings.baseURL),
    authorizationServers: [`${service.settings.baseURL}/api/auth`],
    scopesSupported: [mcpScope, "offline_access"],
  });

  const ownerSession = ownerAuthentication(service).layer;

  // Owner administration and the document need an owner session; issuer actions
  // have their own access rules and must work before anyone has signed in.
  const httpRoutes = Layer.mergeAll(
    Http.layer(owner).pipe(Layer.provide(ownerSession)),
    HttpRouter.add(
      "GET",
      "/openapi.json",
      HttpServerResponse.jsonUnsafe(OpenApi.fromApi(Http.api)),
    ).pipe(Layer.provide(ownerSession)),
    Http.layer(issuer),
  );

  const mcpRoutes = ActionMcp.layerHttp(
    {
      name: "clankerauth-admin",
      version: "0.3.0",
      path: "/mcp",
      // Keep the existing protocol allowlist; native streaming does not expand it.
      protocols: [
        McpProtocol.v2026_07_28,
        McpProtocol.v2025_11_25,
        McpProtocol.v2025_06_18,
        McpProtocol.v2025_03_26,
      ],
      // Native MCP admission needs this allowlist even after owner authentication.
      allowedOrigins: mcpAllowedOrigins,
      instructions:
        "Owner administration. Mutations change authorization policy; create/rotate actions return secrets once.",
    },
    owner,
  ).pipe(
    Layer.provide(
      Authentication.middleware(
        CurrentOwner,
        mcpAuthentication(service).pipe(
          Effect.catch((error) =>
            Effect.flatMap(
              apiErrorResponse(
                error,
                Match.value(error).pipe(
                  Match.tag("Unauthorized", (unauthorized) => ({
                    "www-authenticate": discovery.challenge({
                      error:
                        unauthorized.error === "OAuth access token required"
                          ? undefined
                          : "invalid_token",
                      scope: mcpScope,
                    }),
                  })),
                  Match.tag("Forbidden", () => ({
                    "www-authenticate": discovery.challenge({
                      error: "insufficient_scope",
                      scope: mcpScope,
                    }),
                  })),
                  Match.orElse(() => ({})),
                ),
              ),
              Effect.fail,
            ),
          ),
        ),
      ).layer,
    ),
  );

  // Provider SDK calls do not support interruption. Finish admitted action work
  // before its request scope releases sessions or permits database shutdown.
  return Layer.mergeAll(httpRoutes, mcpRoutes, discovery.layer).pipe(
    Layer.provide(HttpRouter.middleware((effect) => Effect.uninterruptible(effect)).layer),
  );
}
