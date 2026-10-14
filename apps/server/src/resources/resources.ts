import { randomUUID } from "node:crypto";
import { Clock, Context, Effect, Layer, Schema, Scope, Semaphore } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import {
  administrationIdentifier,
  ClientIsAutomatic,
  ClientNotFound,
  CurrentOwner,
  ResourceNotFound,
  type ClientAccess,
  type ClientAccessInput,
  type InternalServerError,
  type ProviderRefused,
  type ResourceId,
} from "@clankerauth/admin-api";
import { Database, persisted, type Sql } from "../platform/sqlite.ts";
import { invalidInput, missing, provider, refused, refusedOrMissing } from "../issuer/errors.ts";
import { Issuer } from "../issuer/issuer.ts";
import { Settings } from "../issuer/settings.ts";
import { clearAuthorization } from "../authorization/authorization.ts";
import {
  accessForClient,
  automatic,
  isAutomatic,
  managed,
  protocolScopes,
  ResourceCatalog,
  scopesOf,
  validateSelection,
  type ResourceValue,
} from "./catalog.ts";

const clientIds = persisted(Schema.Array(Schema.Struct({ clientId: Schema.String })));

const clientOwners = persisted(
  Schema.Array(Schema.Struct({ userId: Schema.NullOr(Schema.String) })),
);

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
      ReadonlyArray<typeof ClientAccess.Type>,
      InternalServerError | Action.InvalidInput | ClientNotFound | ClientIsAutomatic
    >;
    /** Publishes the catalog to the provider and rebuilds every client's copy of it. */
    readonly synchronize: () => Effect.Effect<void, InternalServerError>;
  }
>()("clankerauth/Resources") {
  static readonly layer = Layer.effect(
    Resources,
    Effect.gen(function* () {
      const { sql, transaction } = yield* Database;
      const { auth, publishScopes } = yield* Issuer;
      const catalog = yield* ResourceCatalog;
      const reservedIdentifier = administrationIdentifier((yield* Settings).baseURL);
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
        yield* sql`UPDATE oauthClient SET scopes = ${JSON.stringify(scopes)}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE ${automatic()} AND scopes IS NOT ${JSON.stringify(scopes)}`;

        for (const client of yield* clientIds(
          yield* sql`SELECT clientId FROM oauthClient WHERE ${managed()} ORDER BY clientId`,
        ))
          yield* syncClient(sql, resources, client.clientId);
      });

      const reserved = (identifier: string) =>
        identifier === reservedIdentifier
          ? Effect.fail(invalidInput(["identifier"], "The administration Resource is fixed"))
          : Effect.void;

      const providerHeaders = Effect.flatMap(CurrentOwner, (owner) => owner.providerHeaders);

      yield* synchronize();

      return {
        synchronize,
        create: Effect.fn("Resources.create")(function* (input: ResourceValue) {
          const resource = yield* validateInput(input);
          const headers = yield* providerHeaders;

          if (!(yield* catalog.get(resource.identifier)))
            yield* transaction((query) =>
              clearAuthorization(query, { resource: resource.identifier }),
            );
          yield* refused(
            provider(() =>
              auth.api.adminCreateOAuthResource({
                headers,
                body: {
                  identifier: resource.identifier,
                  name: resource.name,
                  allowedScopes: [...protocolScopes, ...resource.scopes],
                },
              }),
            ),
          );
          yield* synchronize();

          return resource;
        }, serialized),
        update: Effect.fn("Resources.update")(function* (input: ResourceValue) {
          const resource = yield* validateInput(input);
          yield* reserved(resource.identifier);
          const headers = yield* providerHeaders;

          yield* refusedOrMissing(() => ResourceNotFound.of(resource.identifier))(
            provider(() =>
              auth.api.adminUpdateOAuthResource({
                headers,
                params: resourceParams(resource.identifier),
                body: {
                  name: resource.name,
                  allowedScopes: [...protocolScopes, ...resource.scopes],
                },
              }),
            ),
          );
          yield* synchronize();

          return resource;
        }, serialized),
        delete: Effect.fn("Resources.delete")(function* ({ identifier }: typeof ResourceId.Type) {
          yield* reserved(identifier);
          const headers = yield* providerHeaders;

          yield* missing(() => ResourceNotFound.of(identifier))(
            provider(() =>
              auth.api.adminDeleteOAuthResource({ headers, params: resourceParams(identifier) }),
            ),
          );
          yield* transaction((query) => clearAuthorization(query, { resource: identifier }));
          yield* synchronize();

          return { deleted: true };
        }, serialized),
        setAccess: Effect.fn("Resources.setAccess")(function* ({
          client_id: clientId,
          resources: identifiers,
        }: typeof ClientAccessInput.Type) {
          const [client] = yield* clientOwners(
            yield* sql`SELECT userId FROM oauthClient WHERE clientId = ${clientId}`,
          );

          if (!client) return yield* Effect.fail(ClientNotFound.of(clientId));

          if (isAutomatic(client)) return yield* Effect.fail(ClientIsAutomatic.of(clientId));
          const resources = yield* catalog.list();
          yield* validateSelection(resources, identifiers);
          const now = yield* Clock.currentTimeMillis;

          yield* transaction((query) =>
            Effect.gen(function* () {
              const previous = (yield* accessForClient(clientId, query)).map(
                (link) => link.resource,
              );

              for (const identifier of previous.filter((id) => !identifiers.includes(id))) {
                yield* query`DELETE FROM oauthClientResource WHERE clientId = ${clientId} AND resourceId = ${identifier}`;
                yield* clearAuthorization(query, { clientId, resource: identifier });
              }

              for (const identifier of identifiers)
                yield* query`INSERT OR IGNORE INTO oauthClientResource (id, clientId, resourceId, createdAt)
                  VALUES (${randomUUID()}, ${clientId}, ${identifier}, ${new Date(now).toISOString()})`;
              yield* syncClient(query, resources, clientId);
            }),
          );

          return yield* accessForClient(clientId, sql);
        }, serialized),
      };
    }),
  );
}
