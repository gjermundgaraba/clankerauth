import { Clock, Context, Effect, Layer, Schema, Scope, Semaphore } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import {
  CurrentOwner,
  ResourceNotFound,
  type ClientAccess,
  type ClientAccessInput,
  type ClientAccessResult,
  type ClientIsAutomatic,
  type ClientNotFound,
  type InternalServerError,
  type ProviderRefused,
  type ResourceId,
} from "@clankerauth/admin-api";
import { Database, persisted, type Sql } from "../platform/sqlite.ts";
import { invalidInput, provider, refusal } from "../issuer/errors.ts";
import { Issuer } from "../issuer/issuer.ts";
import { clearAuthorization } from "../authorization/authorization.ts";
import { requireManaged } from "../clients/managed.ts";
import {
  accessForClient,
  protocolScopes,
  ResourceCatalog,
  scopesOf,
  validateSelection,
  type ResourceValue,
} from "./catalog.ts";

const clientIds = persisted(Schema.Array(Schema.Struct({ clientId: Schema.String })));

const resourceParams = (identifier: string) => ({
  identifier: encodeURIComponent(identifier),
});

// why: clients send `new URL(resource).href`, the token audience, so only that form matches
const canonical = (identifier: string) => {
  try {
    return new URL(identifier).href === identifier && !identifier.includes("#");
  } catch {
    return false;
  }
};

const validateInput = Effect.fn("Resources.validateInput")(function* (input: ResourceValue) {
  const identifier = input.identifier.trim();
  const name = input.name.trim();
  const scopes = [...new Set(input.scopes.map((scope) => scope.trim()))];

  if (!canonical(identifier))
    return yield* invalidInput(
      ["identifier"],
      "Resource identifiers must be absolute URIs in canonical form, without a fragment",
    );

  const reserved = input.scopes.findIndex((scope) => protocolScopes.includes(scope.trim()));

  if (reserved !== -1)
    return yield* invalidInput(["scopes", reserved], "offline_access is reserved");

  return { identifier, name, scopes } satisfies ResourceValue;
});

type Refusal = InternalServerError | ProviderRefused | Action.InvalidInput;

// why: provider APIs own their transactions; never hold one around them on the shared connection
export class Resources extends Context.Service<
  Resources,
  {
    readonly create: (
      input: ResourceValue,
    ) => Effect.Effect<ResourceValue, Refusal, CurrentOwner | Scope.Scope>;
    readonly update: (
      input: ResourceValue,
    ) => Effect.Effect<ResourceValue, Refusal | ResourceNotFound, CurrentOwner | Scope.Scope>;
    readonly delete: (
      input: typeof ResourceId.Type,
    ) => Effect.Effect<
      { deleted: boolean },
      InternalServerError | Action.InvalidInput | ResourceNotFound,
      CurrentOwner | Scope.Scope
    >;
    /** Links a managed client to exactly these resources, clearing what removed links allowed. */
    readonly setAccess: (
      input: typeof ClientAccessInput.Type,
    ) => Effect.Effect<
      typeof ClientAccessResult.Type,
      InternalServerError | Action.InvalidInput | ClientNotFound | ClientIsAutomatic
    >;
    /** `setAccess` for a client this issuer has just registered, so managed. */
    readonly link: (
      clientId: string,
      identifiers: readonly string[],
    ) => Effect.Effect<
      ReadonlyArray<typeof ClientAccess.Type>,
      InternalServerError | Action.InvalidInput
    >;
  }
>()("clankerauth/Resources") {
  static readonly layer = Layer.effect(
    Resources,
    Effect.gen(function* () {
      const { sql, transaction } = yield* Database;
      const { auth, publishScopes } = yield* Issuer;
      const catalog = yield* ResourceCatalog;
      const mutating = yield* Semaphore.make(1);
      const serialized = <A, E, R>(effect: Effect.Effect<A, E, R>) => mutating.withPermit(effect);

      // why: the provider reads each client's stored scopes; SQL rebuilds them without a session
      const syncClient = Effect.fn("Resources.syncClient")(function* (
        query: Sql,
        resources: readonly ResourceValue[],
        clientId: string,
      ) {
        const links = yield* accessForClient(clientId, query);

        const scopes = JSON.stringify(
          scopesOf(
            resources,
            links.map((link) => link.resource),
          ),
        );

        yield* query`UPDATE oauthClient SET scopes = ${scopes}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${clientId} AND scopes IS NOT ${scopes}`;
      });

      // why: resource and client-scope writes are separate; resync heals a failure between them
      const synchronize = Effect.fn("Resources.synchronize")(function* () {
        const resources = yield* catalog.list();

        const scopes = scopesOf(
          resources,
          resources.map((resource) => resource.identifier),
        );

        yield* publishScopes(scopes);
        yield* sql`UPDATE oauthClient SET scopes = ${JSON.stringify(scopes)}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE userId IS NULL AND scopes IS NOT ${JSON.stringify(scopes)}`;

        for (const client of yield* clientIds(
          yield* sql`SELECT clientId FROM oauthClient WHERE userId IS NOT NULL ORDER BY clientId`,
        ))
          yield* syncClient(sql, resources, client.clientId);
      });

      const reserved = Effect.fn("Resources.reserved")(function* (identifier: string) {
        if ((yield* catalog.get(identifier))?.builtIn)
          return yield* invalidInput(["identifier"], "The administration Resource is fixed");
      });

      const providerHeaders = Effect.flatMap(CurrentOwner, (owner) => owner.providerHeaders);

      yield* synchronize();

      const link = Effect.fn("Resources.link")(function* (
        clientId: string,
        identifiers: readonly string[],
      ) {
        const resources = yield* catalog.list();
        yield* validateSelection(resources, identifiers);
        const now = yield* Clock.currentTimeMillis;

        yield* transaction((query) =>
          Effect.gen(function* () {
            const previous = (yield* accessForClient(clientId, query)).map((link) => link.resource);

            for (const identifier of previous.filter((id) => !identifiers.includes(id))) {
              yield* query`DELETE FROM oauthClientResource WHERE clientId = ${clientId} AND resourceId = ${identifier}`;
              yield* clearAuthorization(query, { clientId, resource: identifier });
            }

            for (const identifier of identifiers)
              yield* query`INSERT OR IGNORE INTO oauthClientResource (id, clientId, resourceId, createdAt)
                VALUES (${crypto.randomUUID()}, ${clientId}, ${identifier}, ${new Date(now).toISOString()})`;
            yield* syncClient(query, resources, clientId);
          }),
        );

        return yield* accessForClient(clientId, sql);
      }, serialized);

      return {
        link,
        create: Effect.fn("Resources.create")(function* (input: ResourceValue) {
          const resource = yield* validateInput(input);
          const headers = yield* providerHeaders;

          if (!(yield* catalog.get(resource.identifier)))
            yield* transaction((query) =>
              clearAuthorization(query, { resource: resource.identifier }),
            );
          yield* provider(
            () =>
              auth.api.adminCreateOAuthResource({
                headers,
                body: {
                  identifier: resource.identifier,
                  name: resource.name,
                  allowedScopes: [...protocolScopes, ...resource.scopes],
                },
              }),
            { refused: refusal },
          );
          yield* synchronize();

          return resource;
        }, serialized),
        update: Effect.fn("Resources.update")(function* (input: ResourceValue) {
          const resource = yield* validateInput(input);
          yield* reserved(resource.identifier);
          const headers = yield* providerHeaders;

          yield* provider(
            () =>
              auth.api.adminUpdateOAuthResource({
                headers,
                params: resourceParams(resource.identifier),
                body: {
                  name: resource.name,
                  allowedScopes: [...protocolScopes, ...resource.scopes],
                },
              }),
            { refused: refusal, missing: () => ResourceNotFound.of(resource.identifier) },
          );
          yield* synchronize();

          return resource;
        }, serialized),
        delete: Effect.fn("Resources.delete")(function* ({ identifier }: typeof ResourceId.Type) {
          yield* reserved(identifier);
          const headers = yield* providerHeaders;

          yield* provider(
            () =>
              auth.api.adminDeleteOAuthResource({ headers, params: resourceParams(identifier) }),
            { missing: () => ResourceNotFound.of(identifier) },
          );
          yield* transaction((query) => clearAuthorization(query, { resource: identifier }));
          yield* synchronize();

          return { deleted: true };
        }, serialized),
        setAccess: Effect.fn("Resources.setAccess")(function* ({
          client_id: clientId,
          resources: identifiers,
        }: typeof ClientAccessInput.Type) {
          yield* requireManaged(clientId, sql);

          return { clientAccess: yield* link(clientId, identifiers) };
        }),
      };
    }),
  );
}
