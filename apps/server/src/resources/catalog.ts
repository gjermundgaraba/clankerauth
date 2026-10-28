import {
  administrationIdentifier,
  ClientAccess,
} from "@gjermundgaraba/clankerauth-admin-api";
import type {
  InternalServerError,
  Resource,
  ResourceSummary,
} from "@gjermundgaraba/clankerauth-admin-api";
import { Context, Effect, Layer, Schema } from "effect";

import { invalidInput } from "../issuer/errors.ts";
import { Settings } from "../issuer/settings.ts";
import { Database, persisted } from "../platform/sqlite.ts";
import type { Sql, SqliteRow } from "../platform/sqlite.ts";

export const exactlyOneResource = "Exactly one configured resource is required";

export const protocolScopes = ["offline_access"];

export type ResourceValue = typeof Resource.Type;

type CatalogResource = typeof ResourceSummary.Type;

const decodeScopes = persisted(
  Schema.fromJsonString(Schema.Array(Schema.String))
);

const ResourceRow = Schema.Struct({
  identifier: Schema.String,
  name: Schema.String,
  allowedScopes: Schema.String,
});

const decodeResourceRow = persisted(ResourceRow);

const accessRows = persisted(Schema.Array(ClientAccess));

export const scopesOf = (
  catalog: readonly ResourceValue[],
  identifiers: readonly string[]
) => [
  ...new Set([
    ...protocolScopes,
    ...identifiers.flatMap(
      (id) =>
        catalog.find((resource) => resource.identifier === id)?.scopes ?? []
    ),
  ]),
];

export const validateSelection = Effect.fn("ResourceCatalog.validateSelection")(
  function* (
    catalog: readonly ResourceValue[],
    identifiers: readonly string[]
  ) {
    const unknown = identifiers.findIndex(
      (id) => !catalog.some((resource) => resource.identifier === id)
    );

    if (unknown !== -1) {
      return yield* invalidInput(["resources", unknown], "Unknown Resource");
    }
  }
);

export const accessForClient = Effect.fn("ResourceCatalog.accessForClient")(
  function* (clientId: string, query: Sql) {
    return yield* accessRows(
      yield* query`SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource WHERE clientId = ${clientId} ORDER BY resourceId`
    );
  }
);

export class ResourceCatalog extends Context.Service<
  ResourceCatalog,
  {
    readonly list: Effect.Effect<CatalogResource[], InternalServerError>;
    readonly get: (
      identifier: string
    ) => Effect.Effect<CatalogResource | undefined, InternalServerError>;
    readonly application: (
      identifier: string
    ) => Effect.Effect<CatalogResource | undefined, InternalServerError>;
    readonly access: Effect.Effect<
      ReadonlyArray<typeof ClientAccess.Type>,
      InternalServerError
    >;
    readonly hasAccess: (
      clientId: string,
      identifier: string
    ) => Effect.Effect<boolean, InternalServerError>;
    readonly scopesFor: (
      identifiers: readonly string[]
    ) => Effect.Effect<
      string[],
      InternalServerError | ReturnType<typeof invalidInput>
    >;
  }
>()("clankerauth/ResourceCatalog") {
  static readonly layer = Layer.effect(
    ResourceCatalog,
    Effect.gen(function* () {
      const { sql } = yield* Database;
      const builtIn = administrationIdentifier((yield* Settings).baseURL);

      const decodeResource = Effect.fn("ResourceCatalog.decode")(function* (
        value: SqliteRow
      ) {
        const row = yield* decodeResourceRow(value);
        const scopes = yield* decodeScopes(row.allowedScopes);

        return {
          identifier: row.identifier,
          name: row.name,
          scopes: scopes.filter((scope) => !protocolScopes.includes(scope)),
          builtIn: row.identifier === builtIn,
        };
      });

      const list = Effect.gen(function* () {
        const rows =
          yield* sql`SELECT identifier, name, allowedScopes FROM oauthResource ORDER BY createdAt, identifier`;

        return yield* Effect.forEach(rows, decodeResource);
      }).pipe(Effect.withSpan("ResourceCatalog.list"));

      const get = Effect.fn("ResourceCatalog.get")(function* (
        identifier: string
      ) {
        const rows =
          yield* sql`SELECT identifier, name, allowedScopes FROM oauthResource WHERE identifier = ${identifier}`;

        return rows[0] ? yield* decodeResource(rows[0]) : undefined;
      });

      return {
        list,
        get,
        application: (identifier) =>
          Effect.map(get(identifier), (resource) =>
            resource?.builtIn === true ? undefined : resource
          ),
        access: Effect.gen(function* () {
          return yield* accessRows(
            yield* sql`SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource ORDER BY clientId, resourceId`
          );
        }).pipe(Effect.withSpan("ResourceCatalog.access")),
        hasAccess: Effect.fn("ResourceCatalog.hasAccess")(function* (
          clientId: string,
          identifier: string
        ) {
          const rows =
            yield* sql`SELECT 1 FROM oauthClient c WHERE c.clientId = ${clientId} AND (c.userId IS NULL
            OR EXISTS (SELECT 1 FROM oauthClientResource l WHERE l.clientId = c.clientId AND l.resourceId = ${identifier}))`;

          return rows.length > 0;
        }),
        scopesFor: Effect.fn("ResourceCatalog.scopesFor")(function* (
          identifiers: readonly string[]
        ) {
          const catalog = yield* list;
          yield* validateSelection(catalog, identifiers);

          return scopesOf(catalog, identifiers);
        }),
      };
    })
  );
}
