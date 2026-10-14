import { Effect, Layer } from "effect";
import { HttpRouter, HttpServerResponse } from "effect/http";
import { OpenApi } from "effect/http-api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import {
  administrationScopes,
  Administration,
  binding,
  IssuerActions,
  ownerSession,
  OwnerHttp,
  OwnerToken,
} from "@clankerauth/admin-api";
import manifest from "../../package.json" with { type: "json" };
import { Clients } from "../clients/clients.ts";
import { Resources } from "../resources/resources.ts";
import { setupActions } from "../owner/setup.ts";
import { administrationResource } from "../owner/administration-resource.ts";
import { ApiKeys } from "../api-keys/api-keys.ts";
import { authorizeOwner, bearerOwner, sessionOwner } from "../owner/authentication.ts";
import { responseCookies } from "./response-cookies.ts";
import { Issuer } from "../issuer/issuer.ts";

export function actionRoutes(mcpAllowedOrigins: readonly string[]) {
  return Layer.unwrap(
    Effect.gen(function* () {
      const { context } = yield* Issuer;
      const clients = yield* Clients;
      const resources = yield* Resources;
      const setup = yield* setupActions;
      const keys = yield* ApiKeys;

      const owner = Action.implement(
        Administration,
        {
          listClients: clients.list,
          createClient: clients.create,
          updateClient: clients.update,
          deleteClient: clients.delete,
          revokeClient: clients.revoke,
          blockClient: clients.block,
          rotateClientSecret: clients.rotate,
          setClientAccess: clients.setAccess,
          createResource: resources.create,
          updateResource: resources.update,
          deleteResource: resources.delete,
          listApiKeys: keys.list,
          createApiKey: keys.create,
          updateApiKey: keys.update,
          deleteApiKey: keys.delete,
        },
        { authorize: authorizeOwner },
      );

      // why: public, so each handler enforces its own access rules
      const issuer = Action.implement(IssuerActions, {
        setupStatus: setup.setupStatus,
        setupOwner: setup.setupOwner,
        keyList: ({ resource }) => keys.keyList(resource),
      });

      const adminResource = yield* administrationResource();

      const session = ownerSession(context.authCookies.sessionToken.name);
      const Http = binding(session);

      const httpRoutes = Layer.mergeAll(
        ActionHttp.layer(Http, owner).pipe(Layer.provide(sessionOwner(session))),
        HttpRouter.add(
          "GET",
          "/openapi.json",
          HttpServerResponse.jsonUnsafe(OpenApi.fromApi(Http.api)),
        ),
        ActionHttp.layer(Http, issuer).pipe(Layer.provide(responseCookies.layer)),
      );

      const tokenRoutes = Layer.mergeAll(
        ActionMcp.layerHttp(owner, {
          name: "clankerauth-admin",
          version: manifest.version,
          // why: native MCP admission checks this allowlist even after authentication
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
