import { randomUUID } from "node:crypto";
import { Clock, Context, Effect, Layer, Schema, Scope, Semaphore } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import {
  administrationIdentifier,
  BadRequest,
  CurrentOwner,
  NotFound,
  type ClientAccess,
  type ClientAccessInput,
  type OwnerError,
  type ResourceId,
} from "@clankerauth/admin-api";
import { Database, persisted, type Sql } from "../platform/sqlite.ts";
import { invalidInput, provider } from "../issuer/errors.ts";
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

// An identifier must already be the string a client sends back. A client asks for
// `new URL(metadata.resource).href`, and the access token's audience is that string,
// so `https://notes.example` (no slash) would be rewritten and stop matching what is
// registered here. Refuse it rather than let a resource server fail at verification.
// RFC 8707 forbids a fragment; in canonical form a `#` can only begin one.
const canonical = (identifier: string) => {
  try {
    return new URL(identifier).href === identifier && !identifier.includes("#");
  } catch {
    return false;
  }
};

// The provider validates identifiers (RFC 8707) and rejects duplicates. The contract's
// schema checks the name and each scope's form.
const validateInput = Effect.fn("Resources.validateInput")(function* (input: ResourceValue) {
  const identifier = input.identifier.trim();
  const name = input.name.trim();
  const scopes = [...new Set(input.scopes.map((scope) => scope.trim()))];

  if (!canonical(identifier))
    return yield* invalidInput(
      ["identifier"],
      "Resource identifiers must be absolute URIs in canonical form, without a fragment",
    );

  // A protocol scope is the provider's, which no resource may declare: name it as sent.
  const reserved = input.scopes.findIndex((scope) => protocolScopes.includes(scope.trim()));

  if (reserved !== -1)
    return yield* invalidInput(["scopes", reserved], "offline_access is reserved");

  return { identifier, name, scopes } satisfies ResourceValue;
});

type Refusal = OwnerError | Action.InvalidInput;

// Provider APIs own their writes and transaction boundaries. Do not hold a separate
// transaction while calling them on the shared connection. Mutations take one permit,
// so their read-diff-write sequences never interleave.
//
// Client access applies to managed clients only: they skip consent, so their links are
// the whole of what they may obtain. An automatic client may ask for any resource, and
// consent decides; the provider's own per-client enforcement is off, so its links are
// neither written nor read.
export class Resources extends Context.Service<
  Resources,
  {
    readonly create: (
      input: ResourceValue,
    ) => Effect.Effect<ResourceValue, Refusal, CurrentOwner | Scope.Scope>;
    readonly update: (
      input: ResourceValue,
    ) => Effect.Effect<ResourceValue, Refusal, CurrentOwner | Scope.Scope>;
    readonly delete: (
      input: typeof ResourceId.Type,
    ) => Effect.Effect<{ deleted: boolean }, Refusal, CurrentOwner | Scope.Scope>;
    /** Links a managed client to exactly these resources, clearing what removed links allowed. */
    readonly setAccess: (
      input: typeof ClientAccessInput.Type,
    ) => Effect.Effect<ReadonlyArray<typeof ClientAccess.Type>, Refusal>;
    /** Publishes the catalog to the provider and rebuilds every client's copy of it. */
    readonly synchronize: () => Effect.Effect<void, OwnerError>;
  }
>()("clankerauth/Resources") {
  /** Publishes the catalog once the provider has seeded the administration resource. */
  static readonly layer = Layer.effect(
    Resources,
    Effect.gen(function* () {
      const { sql, transaction } = yield* Database;
      const { auth, publishScopes } = yield* Issuer;
      const catalog = yield* ResourceCatalog;
      const reservedIdentifier = administrationIdentifier((yield* Settings).baseURL);
      const mutating = yield* Semaphore.make(1);
      const serialized = <A, E, R>(effect: Effect.Effect<A, E, R>) => mutating.withPermit(effect);

      // A client's scope ceiling is a copy the provider reads on every request: the whole
      // catalog for an automatic client, which the provider itself writes at registration
      // and on every CIMD refresh, and the union of its resources' scopes for a managed one.
      // Copies are written directly, so they can be rebuilt without an owner session, and only
      // when they change.
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

      // A resource change and its client copies are separate writes, so a failure between
      // them heals here.
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

      // The caller named it: input this issuer decodes but will not serve.
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

          // Recreating a resource revives nothing, even if its deletion never cleared its authorization.
          // Nothing is granted for an unknown resource, so none can appear before it exists.
          if (!(yield* catalog.get(resource.identifier)))
            yield* transaction((query) =>
              clearAuthorization(query, { resource: resource.identifier }),
            );
          yield* provider(() =>
            auth.api.adminCreateOAuthResource({
              headers,
              body: {
                identifier: resource.identifier,
                name: resource.name,
                allowedScopes: [...protocolScopes, ...resource.scopes],
              },
            }),
          );
          yield* synchronize();

          return resource;
        }, serialized),
        update: Effect.fn("Resources.update")(function* (input: ResourceValue) {
          const resource = yield* validateInput(input);
          yield* reserved(resource.identifier);
          const headers = yield* providerHeaders;

          yield* provider(() =>
            auth.api.adminUpdateOAuthResource({
              headers,
              params: resourceParams(resource.identifier),
              body: {
                name: resource.name,
                allowedScopes: [...protocolScopes, ...resource.scopes],
              },
            }),
          );
          yield* synchronize();

          return resource;
        }, serialized),
        delete: Effect.fn("Resources.delete")(function* ({ identifier }: typeof ResourceId.Type) {
          yield* reserved(identifier);
          const headers = yield* providerHeaders;

          yield* provider(() =>
            auth.api.adminDeleteOAuthResource({ headers, params: resourceParams(identifier) }),
          );
          // The provider removes the resource and foreign keys remove its links; the
          // authorization clients were given for it goes with it. Should this clear fail,
          // create clears it before the identifier can be used again.
          yield* transaction((query) => clearAuthorization(query, { resource: identifier }));
          yield* synchronize();

          return { deleted: true };
        }, serialized),
        // Links and the authorization they allowed change in one local transaction, so
        // restoring access asks again rather than reviving a grant that removal missed.
        setAccess: Effect.fn("Resources.setAccess")(function* ({
          client_id: clientId,
          resources: identifiers,
        }: typeof ClientAccessInput.Type) {
          const [client] = yield* clientOwners(
            yield* sql`SELECT userId FROM oauthClient WHERE clientId = ${clientId}`,
          );

          if (!client) return yield* Effect.fail(new NotFound({ error: "Client not found" }));

          if (isAutomatic(client))
            return yield* Effect.fail(
              new BadRequest({
                error: "Automatic Clients may ask for any Resource; revoke or block them instead",
              }),
            );
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
