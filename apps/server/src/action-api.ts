import { Effect, Layer } from "effect";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import { McpProtocol } from "effect/unstable/ai";
import {
  FetchHttpClient,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";
import { OpenApi } from "effect/unstable/httpapi";
import { Http, Administration, IssuerActions, InternalServerError } from "@clankerauth/api";
import { Resource } from "@gjermundgaraba/clankerauth-node/effect-actions";
import { administration } from "./administration.ts";
import { machineKeys } from "./machine-keys.ts";
import { bearerOwner, sessionOwner } from "./current-owner.ts";
import { responseCookies } from "./response-cookies.ts";
import { mcpResource, mcpScope } from "./resources.ts";
import type { Service } from "./auth.ts";

export function actionRoutes(service: Service, mcpAllowedOrigins: readonly string[]) {
  return Layer.unwrap(
    Effect.gen(function* () {
      const admin = administration(service);
      const keys = machineKeys(service);

      const owner = Administration.implement({
        listClients: admin.list,
        createClient: admin.create,
        updateClient: admin.update,
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
            Effect.mapError(
              () => new InternalServerError({ error: "Request could not be completed" }),
            ),
          ),
        setupOwner: admin.setup,
        verifyApiKey: ({ resource }) =>
          Effect.gen(function* () {
            const request = yield* HttpServerRequest.HttpServerRequest;

            return yield* keys.verify(new Headers(request.headers), resource);
          }),
      });

      // The SDK verifier reads JWKS from this issuer in-process. Provider calls are
      // tracked for shutdown like external ones: the SDK's deadline can abandon a
      // call that must still settle.
      const loopback: typeof fetch = (input, init) => {
        const request = new Request(input, init);
        // Better Auth reads the client address from this header (see ipAddressHeaders in auth.ts).
        request.headers.set("x-clankerauth-peer", "127.0.0.1");

        return service.run(() => service.auth.handler(request));
      };

      const adminResource = yield* Resource.make({
        issuer: `${service.settings.baseURL}/api/auth`,
        resource: mcpResource(service.settings.baseURL),
        scopes: [mcpScope, "offline_access"],
        requiredScopes: [mcpScope],
        // The loopback serves provider routes only, so key verification must never reach the issuer.
        apiKeys: false,
      }).pipe(
        Effect.provide(
          FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, loopback))),
        ),
      );

      // Owner administration needs the dashboard session; issuer actions have
      // their own access rules and must work before anyone has signed in.
      const httpRoutes = Layer.mergeAll(
        Http.layer(owner).pipe(Layer.provide(sessionOwner(service).layer)),
        HttpRouter.add(
          "GET",
          "/openapi.json",
          HttpServerResponse.jsonUnsafe(OpenApi.fromApi(Http.api)),
        ),
        Http.layer(issuer).pipe(Layer.provide(responseCookies.layer)),
      );

      const mcpRoutes = ActionMcp.layerHttp(
        {
          name: "clankerauth-admin",
          version: "0.4.0",
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
          bearerOwner(service, adminResource).combine(Resource.middleware(adminResource)).layer,
        ),
      );

      // Provider SDK calls do not support interruption. Finish admitted action work
      // before its request scope releases sessions or permits database shutdown.
      return Layer.mergeAll(httpRoutes, mcpRoutes, adminResource.discovery.layer).pipe(
        Layer.provide(HttpRouter.middleware((effect) => Effect.uninterruptible(effect)).layer),
      );
    }),
  );
}
