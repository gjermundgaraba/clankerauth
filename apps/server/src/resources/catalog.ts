import { Context, Effect, Layer, Schema } from "effect";
import { ClientAccess, type OwnerError, type Resource } from "@clankerauth/admin-api";
import { Database, persisted, type Sql, type SqliteRow } from "../platform/sqlite.ts";
import { invalidInput } from "../issuer/errors.ts";

/** The administration resource's fixed scopes: `read` allows listing, and `write` allows
 * everything. */
export const administrationScopes = { read: "clankerauth:read", write: "clankerauth:write" };

/**
 * The issuer's own resource: its origin root, as every application's is. It names the
 * token audience of administration, over `/mcp` and `/api/owner/<action>` alike; the
 * dashboard at `/` takes the owner's session cookie, never a token.
 */
export const administrationIdentifier = (baseURL: string) => new URL("/", baseURL).href;

/** Reserved scope names that resources cannot define; the only protocol scope is refresh. */
export const protocolScopes = ["offline_access"];

export type ResourceValue = typeof Resource.Type;

const decodeScopes = persisted(Schema.fromJsonString(Schema.Array(Schema.String)));

const ResourceRow = Schema.Struct({
  identifier: Schema.String,
  name: Schema.String,
  allowedScopes: Schema.String,
});

const decodeResourceRow = persisted(ResourceRow);

const accessRows = persisted(Schema.Array(ClientAccess));

/** Every scope a client may hold across `identifiers`, with the protocol scopes. */
export const scopesOf = (catalog: readonly ResourceValue[], identifiers: readonly string[]) => [
  ...new Set([
    ...protocolScopes,
    ...identifiers.flatMap(
      (id) => catalog.find((resource) => resource.identifier === id)?.scopes ?? [],
    ),
  ]),
];

export const validateSelection = Effect.fn("Resources.validateSelection")(function* (
  catalog: readonly ResourceValue[],
  identifiers: readonly string[],
) {
  const unknown = identifiers.findIndex(
    (id) => !catalog.some((resource) => resource.identifier === id),
  );

  if (unknown !== -1) return yield* invalidInput(["resources", unknown], "Unknown Resource");
});

/** A managed client's resource links, read through `query`, which may be a transaction's. */
export const accessForClient = Effect.fn("Resources.accessForClient")(function* (
  clientId: string,
  query: Sql,
) {
  return yield* accessRows(
    yield* query`SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource WHERE clientId = ${clientId} ORDER BY resourceId`,
  );
});

/** The stored resources and client access, read without the provider. */
export class ResourceCatalog extends Context.Service<
  ResourceCatalog,
  {
    readonly list: () => Effect.Effect<ResourceValue[], OwnerError>;
    readonly get: (identifier: string) => Effect.Effect<ResourceValue | undefined, OwnerError>;
    /** Every managed client's resource links; automatic clients have none. */
    readonly access: () => Effect.Effect<ReadonlyArray<typeof ClientAccess.Type>, OwnerError>;
    /** An automatic client may ask for any resource; a managed one only for its own. */
    readonly hasAccess: (
      clientId: string,
      identifier: string,
    ) => Effect.Effect<boolean, OwnerError>;
    /** The scopes `identifiers` define, refusing an unknown one as invalid input. */
    readonly scopesFor: (
      identifiers: readonly string[],
    ) => Effect.Effect<string[], OwnerError | ReturnType<typeof invalidInput>>;
  }
>()("clankerauth/ResourceCatalog") {
  static readonly layer = Layer.effect(
    ResourceCatalog,
    Effect.gen(function* () {
      const { sql } = yield* Database;

      const decodeResource = Effect.fn("Resources.decode")(function* (value: SqliteRow) {
        const row = yield* decodeResourceRow(value);
        const scopes = yield* decodeScopes(row.allowedScopes);

        return {
          identifier: row.identifier,
          name: row.name,
          scopes: scopes.filter((scope) => !protocolScopes.includes(scope)),
        };
      });

      const list = Effect.fn("Resources.list")(function* () {
        const rows =
          yield* sql`SELECT identifier, name, allowedScopes FROM oauthResource ORDER BY createdAt, identifier`;

        return yield* Effect.forEach(rows, decodeResource);
      });

      return {
        list,
        get: Effect.fn("Resources.get")(function* (identifier: string) {
          const rows =
            yield* sql`SELECT identifier, name, allowedScopes FROM oauthResource WHERE identifier = ${identifier}`;

          return rows[0] ? yield* decodeResource(rows[0]) : undefined;
        }),
        access: Effect.fn("Resources.access")(function* () {
          return yield* accessRows(
            yield* sql`SELECT clientId AS client_id, resourceId AS resource FROM oauthClientResource ORDER BY clientId, resourceId`,
          );
        }),
        hasAccess: Effect.fn("Resources.hasAccess")(function* (
          clientId: string,
          identifier: string,
        ) {
          const rows =
            yield* sql`SELECT 1 FROM oauthClient c WHERE c.clientId = ${clientId} AND (c.userId IS NULL
            OR EXISTS (SELECT 1 FROM oauthClientResource l WHERE l.clientId = c.clientId AND l.resourceId = ${identifier}))`;

          return rows.length > 0;
        }),
        scopesFor: Effect.fn("Resources.scopesFor")(function* (identifiers: readonly string[]) {
          const catalog = yield* list();
          yield* validateSelection(catalog, identifiers);

          return scopesOf(catalog, identifiers);
        }),
      };
    }),
  );
}
