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
} from "@gjermundgaraba/clankerauth-admin-api";
import manifest from "../../package.json" with { type: "json" };
import { Clients } from "../clients/clients.ts";
import { Resources } from "../resources/resources.ts";
import { setupActions } from "../owner/setup.ts";
import { administrationResource } from "../owner/administration-resource.ts";
import { ApiKeys } from "../api-keys/api-keys.ts";
import { authorizeOwner, bearerOwner, sessionOwner } from "../owner/authentication.ts";
import { responseCookies } from "./response-cookies.ts";
import { Issuer } from "../issuer/issuer.ts";

// why: MCP tool calls run outside the uninterruptible route middleware, and an abort interrupts them
const settles =
  <A extends ReadonlyArray<unknown>, B, E, R>(handler: (...args: A) => Effect.Effect<B, E, R>) =>
  (...args: A) =>
    Effect.uninterruptible(handler(...args));

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
          listClients: settles(clients.list),
          createClient: settles(clients.create),
          updateClient: settles(clients.update),
          deleteClient: settles(clients.delete),
          revokeClient: settles(clients.revoke),
          blockClient: settles(clients.block),
          rotateClientSecret: settles(clients.rotate),
          setClientAccess: settles(resources.setAccess),
          getResource: settles(resources.get),
          putResource: settles(resources.put),
          deleteResource: settles(resources.delete),
          listApiKeys: settles(keys.list),
          createApiKey: settles(keys.create),
          updateApiKey: settles(keys.update),
          deleteApiKey: settles(keys.delete),
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
