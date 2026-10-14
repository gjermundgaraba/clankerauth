import { Clock, Context, DateTime, Effect, Layer, Record, Schema, type Scope } from "effect";
import type * as Action from "@gjermundgaraba/effect-actions/Action";
import * as KeyList from "@gjermundgaraba/clankerauth-sdk/key-list";
import {
  CurrentOwner,
  KeyPermissions,
  type ApiKeyId,
  type ApiKeyInput,
  type ApiKeyUpdate,
  type ApiKey,
  ApiKeyNotFound,
  type InternalServerError,
  type ProviderRefused,
} from "@clankerauth/admin-api";
import { Database } from "../platform/sqlite.ts";
import { Issuer } from "../issuer/issuer.ts";
import { ResourceCatalog } from "../resources/catalog.ts";
import { invalidInput, provider, refusal } from "../issuer/errors.ts";

const permissions = Schema.decodeUnknownEffect(KeyPermissions);

const storedKey = Schema.decodeUnknownEffect(
  Schema.Struct({
    id: Schema.String,
    key: Schema.String,
    referenceId: Schema.String,
    expiresAt: Schema.NullOr(Schema.DateTimeUtcFromString),
    permissions: Schema.NullOr(Schema.fromJsonString(KeyPermissions)),
  }),
);

const summary = Effect.fnUntraced(function* (key: {
  id: string;
  name?: string | null;
  enabled: boolean;
  permissions?: unknown;
  expiresAt?: Date | null;
  createdAt: Date;
}) {
  return {
    keyId: key.id,
    name: key.name ?? "",
    enabled: key.enabled,
    permissions: yield* permissions(key.permissions ?? {}).pipe(
      Effect.catch(() =>
        Effect.as(
          Effect.logWarning(
            "An API key's stored permissions do not decode; it is listed with none",
            {
              keyId: key.id,
            },
          ),
          {},
        ),
      ),
    ),
    expiresAt: key.expiresAt ? DateTime.fromDateUnsafe(key.expiresAt) : null,
    createdAt: DateTime.fromDateUnsafe(key.createdAt),
  };
});

type Refusal = InternalServerError | ProviderRefused | Action.InvalidInput;

type Summary = typeof ApiKey.Type;

export class ApiKeys extends Context.Service<
  ApiKeys,
  {
    readonly list: () => Effect.Effect<
      { keys: ReadonlyArray<Summary> },
      InternalServerError,
      CurrentOwner | Scope.Scope
    >;
    /** Creates a key; its secret is returned once. */
    readonly create: (
      input: typeof ApiKeyInput.Type,
    ) => Effect.Effect<Summary & { key: string }, Refusal, CurrentOwner>;
    readonly update: (
      input: typeof ApiKeyUpdate.Type,
    ) => Effect.Effect<Summary, Refusal | ApiKeyNotFound, CurrentOwner>;
    readonly delete: (
      input: typeof ApiKeyId.Type,
    ) => Effect.Effect<
      { deleted: boolean },
      InternalServerError | ApiKeyNotFound,
      CurrentOwner | Scope.Scope
    >;
    /**
     * Every enabled, unexpired key granted on the resource, with the scopes it still
     * defines, sealed and signed for offline verification. An unknown resource, and the
     * administration resource, which keys never reach, get a list with no entries.
     */
    readonly keyList: (identifier: string) => Effect.Effect<{ list: string }, InternalServerError>;
  }
>()("clankerauth/ApiKeys") {
  static readonly layer = Layer.effect(
    ApiKeys,
    Effect.gen(function* () {
      const { auth } = yield* Issuer;
      const { sql } = yield* Database;
      const catalog = yield* ResourceCatalog;

      const validate = Effect.fn("ApiKeys.validate")(function* (
        grants: typeof KeyPermissions.Type | undefined,
      ) {
        if (grants === undefined) return;

        for (const [identifier, scopes] of Object.entries(grants)) {
          const resource = yield* catalog.get(identifier);

          if (resource?.builtIn)
            return yield* invalidInput(
              ["permissions", identifier],
              "Administration requires OAuth access tokens, not API keys",
            );

          if (!resource || scopes.some((scope) => !resource.scopes.includes(scope)))
            return yield* invalidInput(
              ["permissions", identifier],
              "Select explicitly granted, currently available Resource scopes",
            );
        }
      });

      return {
        list: Effect.fn("ApiKeys.list")(function* () {
          const { providerHeaders } = yield* CurrentOwner;
          const headers = yield* providerHeaders;

          const result = yield* provider(() =>
            auth.api.listApiKeys({
              headers,
              query: { sortBy: "createdAt", sortDirection: "asc" },
            }),
          );

          return { keys: yield* Effect.forEach(result.apiKeys, summary) };
        }),
        create: Effect.fn("ApiKeys.create")(function* (input: typeof ApiKeyInput.Type) {
          const owner = yield* CurrentOwner;
          yield* validate(input.permissions);

          const expiresIn =
            input.expiresAt === null
              ? null
              : (DateTime.toEpochMillis(input.expiresAt) - (yield* Clock.currentTimeMillis)) / 1000;

          if (expiresIn !== null && expiresIn < 1)
            return yield* invalidInput(["expiresAt"], "Expiry must be in the future");

          const key = yield* provider(
            () =>
              auth.api.createApiKey({
                body: {
                  userId: owner.userId,
                  name: input.name.trim(),
                  permissions: Record.map(input.permissions, (scopes) => [...scopes]),
                  expiresIn,
                },
              }),
            { refused: refusal },
          );

          return { ...(yield* summary(key)), key: key.key };
        }),
        update: Effect.fn("ApiKeys.update")(function* (input: typeof ApiKeyUpdate.Type) {
          const owner = yield* CurrentOwner;
          yield* validate(input.permissions);

          return yield* summary(
            yield* provider(
              () =>
                auth.api.updateApiKey({
                  body: {
                    userId: owner.userId,
                    keyId: input.keyId,
                    name: input.name?.trim(),
                    enabled: input.enabled,
                    permissions:
                      input.permissions && Record.map(input.permissions, (scopes) => [...scopes]),
                  },
                }),
              { refused: refusal, missing: () => ApiKeyNotFound.of(input.keyId) },
            ),
          );
        }),
        delete: Effect.fn("ApiKeys.delete")(function* ({ keyId }: typeof ApiKeyId.Type) {
          const { providerHeaders } = yield* CurrentOwner;
          const headers = yield* providerHeaders;
          yield* provider(() => auth.api.deleteApiKey({ headers, body: { keyId } }), {
            missing: () => ApiKeyNotFound.of(keyId),
          });

          return { deleted: true };
        }),
        keyList: Effect.fn("ApiKeys.keyList")(function* (identifier: string) {
          const now = yield* Clock.currentTimeMillis;
          const available = (yield* catalog.application(identifier))?.scopes ?? [];

          const rows = available.length
            ? yield* sql`
            SELECT id, key, referenceId, expiresAt, permissions FROM apikey
            WHERE enabled = 1 AND (expiresAt IS NULL OR expiresAt > ${new Date(now).toISOString()})
          `
            : [];

          // why: a key's digest is its entry's secret, so only the key ID may reach the log
          const entries = yield* Effect.forEach(rows, (row) =>
            Effect.gen(function* () {
              const key = yield* storedKey(row);

              const scopes = (key.permissions?.[identifier] ?? []).filter((scope) =>
                available.includes(scope),
              );

              if (!scopes.length) return [];

              const entry = yield* Effect.tryPromise(() =>
                KeyList.seal(new Uint8Array(Buffer.from(key.key, "base64url")), identifier, {
                  keyId: key.id,
                  ownerId: key.referenceId,
                  scopes,
                  expiresAt: key.expiresAt === null ? null : DateTime.toEpochMillis(key.expiresAt),
                }),
              );

              return [entry];
            }).pipe(
              Effect.catch(() =>
                Effect.as(
                  Effect.logWarning(
                    "An API key row cannot be listed; it is left out of key lists",
                    {
                      keyId: row.id,
                    },
                  ),
                  [],
                ),
              ),
            ),
          );

          const iat = Math.floor(now / 1000);

          const { token } = yield* provider(() =>
            auth.api.signDocument({
              body: {
                typ: KeyList.type,
                payload: {
                  aud: identifier,
                  iat,
                  exp: iat + KeyList.lifetime,
                  keys: entries.flat(),
                },
              },
            }),
          );

          return { list: token };
        }),
      };
    }),
  );
}
