import { Effect, Layer } from "effect";
import { HttpRouter, HttpServerResponse } from "effect/http";
import { OpenApi } from "effect/http-api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import {
  Administration,
  binding,
  IssuerActions,
  InternalServerError,
  ownerSession,
  OwnerHttp,
  OwnerToken,
} from "@clankerauth/admin-api";
import manifest from "../../package.json" with { type: "json" };
import { clientActions } from "../clients/actions.ts";
import { resourceActions } from "../resources/actions.ts";
import { setupActions } from "../owner/setup.ts";
import { administrationResource } from "../owner/administration-resource.ts";
import { machineKeys } from "../api-keys/api-keys.ts";
import { authorizeOwner, bearerOwner, sessionOwner } from "../owner/authentication.ts";
import { administrationScopes } from "../resources/resources.ts";
import { responseCookies } from "./response-cookies.ts";
import { Auth } from "../issuer/issuer.ts";

export function actionRoutes(mcpAllowedOrigins: readonly string[]) {
  return Layer.unwrap(
    Effect.gen(function* () {
      const service = yield* Auth;
      const admin = yield* clientActions;
      const resources = yield* resourceActions;
      const setup = yield* setupActions;
      const keys = yield* machineKeys;

      const owner = Action.implement(
        Administration,
        {
          listClients: admin.list,
          createClient: admin.create,
          updateClient: admin.update,
          deleteClient: admin.delete,
          revokeClient: admin.revoke,
          blockClient: admin.block,
          rotateClientSecret: admin.rotate,
          setClientAccess: admin.access,
          createResource: resources.createResource,
          updateResource: resources.updateResource,
          deleteResource: resources.deleteResource,
          listApiKeys: keys.list,
          createApiKey: keys.create,
          updateApiKey: keys.update,
          deleteApiKey: keys.delete,
        },
        { authorize: authorizeOwner },
      );

      // Public: their handlers hold their own access rules, and no identity reaches them.
      const issuer = Action.implement(IssuerActions, {
        setupStatus: () =>
          service.owner().pipe(
            Effect.map((owner) => ({ required: !owner })),
            Effect.mapError(
              () => new InternalServerError({ error: "Request could not be completed" }),
            ),
          ),
        setupOwner: setup.setupOwner,
        keyList: ({ resource }) => keys.keyList(resource),
      });

      const adminResource = yield* administrationResource();

      // The session cookie as this deployment names it, `__Secure-` prefixed over HTTPS, which
      // the binding's routes read and its OpenAPI document names.
      const session = ownerSession(service.context.authCookies.sessionToken.name);
      const Http = binding(session);

      // Owner administration needs the dashboard session; issuer actions are public, with
      // their own access rules, and must work before anyone has signed in.
      const httpRoutes = Layer.mergeAll(
        ActionHttp.layer(Http, owner).pipe(Layer.provide(sessionOwner(session))),
        HttpRouter.add(
          "GET",
          "/openapi.json",
          HttpServerResponse.jsonUnsafe(OpenApi.fromApi(Http.api)),
        ),
        ActionHttp.layer(Http, issuer).pipe(Layer.provide(responseCookies.layer)),
      );

      // A token client's administration, over MCP or HTTP, under one provider, which also
      // publishes the resource's discovery. Tools are listed to every caller; a read-only
      // token is refused per call, as it is per request over HTTP.
      const tokenRoutes = Layer.mergeAll(
        ActionMcp.layerHttp(owner, {
          name: "clankerauth-admin",
          version: manifest.version,
          // Native MCP admission needs this allowlist even after owner authentication.
          allowedOrigins: mcpAllowedOrigins,
          instructions: `Owner administration. Listing needs ${administrationScopes.read} or ${administrationScopes.write}; every other action changes authorization policy and needs ${administrationScopes.write}. Create and rotate actions return secrets once.`,
          authentication: OwnerToken,
        }),
        ActionHttp.layer(OwnerHttp, owner),
      ).pipe(Layer.provide(bearerOwner(adminResource)));

      return Layer.mergeAll(httpRoutes, tokenRoutes);
    }),
  );
}
