import { Effect, Layer } from "effect";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import { HttpServerRequest } from "effect/unstable/http";
import {
  Http,
  Administration,
  Forbidden,
  IssuerActions,
  InternalServerError,
} from "@clankerauth/admin-api";
import manifest from "../package.json" with { type: "json" };
import { administration } from "./administration.ts";
import { administrationResource } from "./administration-resource.ts";
import { machineKeys } from "./machine-keys.ts";
import { bearerOwner, CurrentOwner, sessionOwner } from "./current-owner.ts";
import { administrationScopes } from "./resources.ts";
import { responseCookies } from "./response-cookies.ts";
import { Auth } from "./auth.ts";

export function actionRoutes(mcpAllowedOrigins: readonly string[]) {
  return Layer.unwrap(
    Effect.gen(function* () {
      const service = yield* Auth;
      const admin = yield* administration;
      const keys = yield* machineKeys;

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

      const adminResource = yield* administrationResource();

      // Owner administration needs the dashboard session; issuer actions have
      // their own access rules and must work before anyone has signed in.
      const httpRoutes = Layer.mergeAll(
        Http.layer([owner]).pipe(Layer.provide((yield* sessionOwner).layer)),
        Http.openApi("/openapi.json"),
        Http.layer([issuer]).pipe(Layer.provide(responseCookies.layer)),
      );

      const mcpRoutes = ActionMcp.layerHttp([owner], {
        name: "clankerauth-admin",
        version: manifest.version,
        path: "/mcp",
        // Native MCP admission needs this allowlist even after owner authentication.
        allowedOrigins: mcpAllowedOrigins,
        instructions: `Owner administration. Listing needs ${administrationScopes.read} or ${administrationScopes.write}; every other action changes authorization policy and needs ${administrationScopes.write}. Create and rotate actions return secrets once.`,
        // Tools are listed to every caller; a read-only token is refused per call.
        errors: [Forbidden],
        before: (action) =>
          action.access === "read"
            ? Effect.void
            : Effect.flatMap(CurrentOwner, ({ writable }) =>
                writable
                  ? Effect.void
                  : Effect.fail(
                      new Forbidden({
                        error: `This action requires the ${administrationScopes.write} scope`,
                      }),
                    ),
              ),
      }).pipe(Layer.provide((yield* bearerOwner(adminResource)).layer));

      return Layer.mergeAll(httpRoutes, mcpRoutes, adminResource.discovery.layer);
    }),
  );
}
