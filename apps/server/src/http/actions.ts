import {
  administrationScopes,
  Administration,
  binding,
  IssuerActions,
  ownerSession,
  OwnerHttp,
  OwnerToken,
} from "@gjermundgaraba/clankerauth-admin-api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import { Effect, Layer } from "effect";
import { HttpRouter, HttpServerResponse } from "effect/http";
import { OpenApi } from "effect/http-api";

import manifest from "../../package.json" with { type: "json" };
import { ApiKeys } from "../api-keys/api-keys.ts";
import { Clients } from "../clients/clients.ts";
import { Issuer } from "../issuer/issuer.ts";
import { administrationResource } from "../owner/administration-resource.ts";
import {
  authorizeOwner,
  bearerOwner,
  sessionOwner,
} from "../owner/authentication.ts";
import { setupActions } from "../owner/setup.ts";
import { Resources } from "../resources/resources.ts";
import { responseCookies } from "./response-cookies.ts";

const uninterruptibleForMcp =
  <A extends readonly unknown[], B, E, R>(
    handler: (...args: A) => Effect.Effect<B, E, R>
  ) =>
  (...args: A) =>
    Effect.uninterruptible(handler(...args));

export const actionRoutes = (mcpAllowedOrigins: readonly string[]) =>
  Layer.unwrap(
    Effect.gen(function* () {
      const { context } = yield* Issuer;
      const clients = yield* Clients;
      const resources = yield* Resources;
      const setup = yield* setupActions;
      const keys = yield* ApiKeys;

      const owner = Action.implement(
        Administration,
        {
          listClients: uninterruptibleForMcp(() => clients.list),
          createClient: uninterruptibleForMcp(clients.create),
          updateClient: uninterruptibleForMcp(clients.update),
          deleteClient: uninterruptibleForMcp(clients.delete),
          revokeClient: uninterruptibleForMcp(clients.revoke),
          blockClient: uninterruptibleForMcp(clients.block),
          rotateClientSecret: uninterruptibleForMcp(clients.rotate),
          setClientAccess: uninterruptibleForMcp(resources.setAccess),
          getResource: uninterruptibleForMcp(resources.get),
          putResource: uninterruptibleForMcp(resources.put),
          deleteResource: uninterruptibleForMcp(resources.delete),
          listApiKeys: uninterruptibleForMcp(() => keys.list),
          createApiKey: uninterruptibleForMcp(keys.create),
          updateApiKey: uninterruptibleForMcp(keys.update),
          deleteApiKey: uninterruptibleForMcp(keys.delete),
        },
        { authorize: authorizeOwner }
      );

      const issuer = Action.implement(IssuerActions, {
        setupStatus: setup.setupStatus,
        setupOwner: setup.setupOwner,
        keyList: ({ resource }) => keys.keyList(resource),
      });

      const adminResource = yield* administrationResource();

      const session = ownerSession(context.authCookies.sessionToken.name);
      const Http = binding(session);

      const httpRoutes = Layer.mergeAll(
        ActionHttp.layer(Http, owner).pipe(
          Layer.provide(sessionOwner(session))
        ),
        HttpRouter.add(
          "GET",
          "/openapi.json",
          HttpServerResponse.jsonUnsafe(OpenApi.fromApi(Http.api))
        ),
        ActionHttp.layer(Http, issuer).pipe(
          Layer.provide(responseCookies.layer)
        )
      );

      const tokenRoutes = Layer.mergeAll(
        ActionMcp.layerHttp(owner, {
          name: "clankerauth-admin",
          version: manifest.version,
          allowedOrigins: mcpAllowedOrigins,
          instructions: `Owner administration. Listing needs ${administrationScopes.read} or ${administrationScopes.write}; every other action changes authorization policy and needs ${administrationScopes.write}. Create and rotate actions return secrets once.`,
          authentication: OwnerToken,
        }),
        ActionHttp.layer(OwnerHttp, owner)
      ).pipe(Layer.provide(bearerOwner(adminResource)));

      return Layer.mergeAll(httpRoutes, tokenRoutes);
    })
  );
