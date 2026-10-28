import {
  CurrentOwner,
  ResourceNotFound,
} from "@gjermundgaraba/clankerauth-admin-api";
import type {
  ClientAccess,
  ClientAccessInput,
  ClientAccessResult,
  ClientIsAutomatic,
  ClientNotFound,
  InternalServerError,
  ProviderRefused,
  ResourceId,
  ResourceSummary,
} from "@gjermundgaraba/clankerauth-admin-api";
import type * as Action from "@gjermundgaraba/effect-actions/Action";
import type { Scope } from "effect";
import {
  Clock,
  Context,
  Effect,
  Layer,
  Redacted,
  Schema,
  Semaphore,
} from "effect";

import { clearAuthorization } from "../authorization/authorization.ts";
import { requireManaged } from "../clients/managed.ts";
import { invalidInput, provider, refusal } from "../issuer/errors.ts";
import { Issuer } from "../issuer/issuer.ts";
import { Database, persisted } from "../platform/sqlite.ts";
import type { Sql } from "../platform/sqlite.ts";
import {
  accessForClient,
  protocolScopes,
  ResourceCatalog,
  scopesOf,
  validateSelection,
} from "./catalog.ts";
import type { ResourceValue } from "./catalog.ts";

const clientIds = persisted(
  Schema.Array(Schema.Struct({ clientId: Schema.String }))
);

const resourceParams = (identifier: string) => ({
  identifier: encodeURIComponent(identifier),
});

const canonical = (identifier: string) => {
  try {
    return new URL(identifier).href === identifier && !identifier.includes("#");
  } catch {
    return false;
  }
};

const validateInput = Effect.fn("Resources.validateInput")(function* (
  input: ResourceValue
) {
  if (!canonical(input.identifier)) {
    return yield* invalidInput(
      ["identifier"],
      "Resource identifiers must be absolute URIs in canonical form, without a fragment"
    );
  }

  const reserved = input.scopes.findIndex((scope) =>
    protocolScopes.includes(scope)
  );

  if (reserved !== -1) {
    return yield* invalidInput(
      ["scopes", reserved],
      "offline_access is reserved"
    );
  }

  return {
    ...input,
    scopes: [...new Set(input.scopes)],
  } satisfies ResourceValue;
});

const reserved = (resource: typeof ResourceSummary.Type | undefined) =>
  resource?.builtIn === true
    ? Effect.fail(
        invalidInput(["identifier"], "The administration Resource is fixed")
      )
    : Effect.void;

type Refusal = InternalServerError | ProviderRefused | Action.InvalidInput;

export class Resources extends Context.Service<
  Resources,
  {
    readonly get: (
      input: typeof ResourceId.Type
    ) => Effect.Effect<
      typeof ResourceSummary.Type,
      InternalServerError | ResourceNotFound
    >;
    readonly put: (
      input: ResourceValue
    ) => Effect.Effect<
      { resource: ResourceValue; created: boolean },
      Refusal,
      CurrentOwner | Scope.Scope
    >;
    readonly delete: (
      input: typeof ResourceId.Type
    ) => Effect.Effect<
      { deleted: boolean },
      InternalServerError | Action.InvalidInput | ResourceNotFound,
      CurrentOwner | Scope.Scope
    >;
    readonly setAccess: (
      input: typeof ClientAccessInput.Type
    ) => Effect.Effect<
      typeof ClientAccessResult.Type,
      | InternalServerError
      | Action.InvalidInput
      | ClientNotFound
      | ClientIsAutomatic
    >;
    readonly link: (
      clientId: string,
      identifiers: readonly string[]
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

      const serialized = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
        mutating.withPermit(effect);

      const syncClient = Effect.fn("Resources.syncClient")(function* (
        query: Sql,
        resources: readonly ResourceValue[],
        clientId: string
      ) {
        const links = yield* accessForClient(clientId, query);

        const scopes = JSON.stringify(
          scopesOf(
            resources,
            links.map((link) => link.resource)
          )
        );

        yield* query`UPDATE oauthClient SET scopes = ${scopes}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE clientId = ${clientId} AND scopes IS NOT ${scopes}`;
      });

      const synchronize = Effect.fn("Resources.synchronize")(function* () {
        const resources = yield* catalog.list;

        const scopes = scopesOf(
          resources,
          resources.map((resource) => resource.identifier)
        );

        yield* publishScopes(scopes);
        yield* sql`UPDATE oauthClient SET scopes = ${JSON.stringify(scopes)}, updatedAt = ${yield* Clock.currentTimeMillis} WHERE userId IS NULL AND scopes IS NOT ${JSON.stringify(scopes)}`;

        for (const client of yield* clientIds(
          yield* sql`SELECT clientId FROM oauthClient WHERE userId IS NOT NULL ORDER BY clientId`
        )) {
          yield* syncClient(sql, resources, client.clientId);
        }
      });

      const providerHeaders = Effect.flatMap(
        CurrentOwner,
        (owner) => owner.providerHeaders
      );

      yield* synchronize();

      const link = Effect.fn("Resources.link")(function* (
        clientId: string,
        identifiers: readonly string[]
      ) {
        const resources = yield* catalog.list;
        yield* validateSelection(resources, identifiers);
        const now = yield* Clock.currentTimeMillis;

        yield* transaction((query) =>
          Effect.gen(function* () {
            const previous = (yield* accessForClient(clientId, query)).map(
              ({ resource }) => resource
            );

            for (const identifier of previous.filter(
              (id) => !identifiers.includes(id)
            )) {
              yield* query`DELETE FROM oauthClientResource WHERE clientId = ${clientId} AND resourceId = ${identifier}`;
              yield* clearAuthorization(query, {
                clientId,
                resource: identifier,
              });
            }

            for (const identifier of identifiers) {
              yield* query`INSERT OR IGNORE INTO oauthClientResource (id, clientId, resourceId, createdAt)
                VALUES (${crypto.randomUUID()}, ${clientId}, ${identifier}, ${new Date(now).toISOString()})`;
            }

            yield* syncClient(query, resources, clientId);
          })
        );

        return yield* accessForClient(clientId, sql);
      }, serialized);

      return {
        link,
        get: Effect.fn("Resources.get")(function* ({
          identifier,
        }: typeof ResourceId.Type) {
          const resource = yield* catalog.get(identifier);

          return resource ?? (yield* ResourceNotFound.of(identifier));
        }),
        put: Effect.fn("Resources.put")(function* (input: ResourceValue) {
          const resource = yield* validateInput(input);
          const existing = yield* catalog.get(resource.identifier);
          yield* reserved(existing);
          const headers = Redacted.value(yield* providerHeaders);
          const allowedScopes = [...protocolScopes, ...resource.scopes];

          if (existing === undefined) {
            yield* transaction((query) =>
              clearAuthorization(query, { resource: resource.identifier })
            );
            yield* provider(
              async () =>
                await auth.api.adminCreateOAuthResource({
                  headers,
                  body: {
                    identifier: resource.identifier,
                    name: resource.name,
                    allowedScopes,
                  },
                }),
              { refused: refusal }
            );
          } else {
            yield* provider(
              async () =>
                await auth.api.adminUpdateOAuthResource({
                  headers,
                  params: resourceParams(resource.identifier),
                  body: { name: resource.name, allowedScopes },
                }),
              { refused: refusal }
            );
          }

          yield* synchronize();

          return { resource, created: existing === undefined };
        }, serialized),
        delete: Effect.fn("Resources.delete")(function* ({
          identifier,
        }: typeof ResourceId.Type) {
          yield* reserved(yield* catalog.get(identifier));
          const headers = Redacted.value(yield* providerHeaders);

          yield* provider(
            async () =>
              await auth.api.adminDeleteOAuthResource({
                headers,
                params: resourceParams(identifier),
              }),
            { missing: () => ResourceNotFound.of(identifier) }
          );
          yield* transaction((query) =>
            clearAuthorization(query, { resource: identifier })
          );
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
    })
  );
}
