import { Effect, Layer } from "effect";
import { NodeHttpServer } from "@effect/platform-node";
import * as Authentication from "@gjermundgaraba/effect-actions/authentication";
import * as ActionMcp from "@gjermundgaraba/effect-actions/mcp";
import { McpProtocol } from "effect/unstable/ai";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import {
  Actions,
  Http,
  errors,
  Administration,
  IssuerActions,
  Forbidden,
  InternalServerError,
  schemaError,
} from "@clankerauth/api";
import { administration } from "./administration.ts";
import { machineKeys } from "./machine-keys.ts";
import { CurrentOwner, ownerAuthentication } from "./current-owner.ts";
import { mcpAuthentication } from "./mcp-auth.ts";
import { mcpResource, mcpScope } from "./resources.ts";
import type { Service } from "./auth.ts";

export function actionApi(service: Service, mcpAllowedOrigins: readonly string[]) {
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
  const discovery = ActionMcp.protectedResource({
    resource: mcpResource(service.settings.baseURL),
    authorizationServers: [`${service.settings.baseURL}/api/auth`],
    scopesSupported: [mcpScope, "offline_access"],
  });
  const ownerRoutes = Layer.mergeAll(
    Http.layer(owner),
    HttpRouter.add(
      "GET",
      "/openapi.json",
      HttpServerResponse.json(Http.openapi(Actions)).pipe(Effect.orDie),
    ),
  ).pipe(Layer.provide(ownerAuthentication(service).layer));
  const mcpRoutes = ActionMcp.layer(owner, {
    schemaError,
    name: "clankerauth-admin",
    version: "0.3.0",
    path: "/mcp",
    // Unary Streamable HTTP works through the buffered Node bridge. Historical
    // 2024 two-endpoint SSE and long-lived streaming are not supported here.
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
  }).pipe(
    Layer.provide(
      Authentication.middleware(CurrentOwner, {
        errors,
        authenticate: mcpAuthentication(service),
        headers: (error) =>
          error._tag === "Unauthorized" || error._tag === "Forbidden"
            ? {
                "www-authenticate": discovery.challenge({
                  error:
                    error._tag === "Forbidden"
                      ? "insufficient_scope"
                      : error.error === "OAuth access token required"
                        ? undefined
                        : "invalid_token",
                  scope: mcpScope,
                }),
              }
            : {},
      }).layer,
    ),
  );
  const routes = Layer.mergeAll(Http.layer(issuer), ownerRoutes, mcpRoutes, discovery.layer).pipe(
    Layer.provide(NodeHttpServer.layerHttpServices),
  );
  return HttpRouter.toWebHandler(routes, { disableLogger: true });
}
