import { Clock, DateTime, Effect, Schema } from "effect";
import * as KeyList from "@gjermundgaraba/clankerauth-sdk/key-list";
import {
  BadRequest,
  KeyPermissions,
  type ApiKeyId,
  type ApiKeyInput,
  type ApiKeyUpdate,
} from "@clankerauth/admin-api";
import { Auth } from "./auth.ts";
import { mcpResource } from "./resources.ts";
import { CurrentOwner } from "./current-owner.ts";
import { provider } from "./api-errors.ts";

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
    // Permissions that no longer decode grant nothing: key lists already leave the key
    // out, and it is listed with none, so the owner can still see and delete it.
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

export const machineKeys = Effect.map(Auth, (service) => {
  const validate = Effect.fn("MachineKeys.validate")(function* (
    name: string | undefined,
    grants: typeof KeyPermissions.Type | undefined,
  ) {
    if (name !== undefined && (!name.trim() || name.length > 100))
      return yield* Effect.fail(new BadRequest({ error: "Key names require 1–100 characters" }));

    if (grants === undefined) return;

    if (!Object.keys(grants).length)
      return yield* Effect.fail(
        new BadRequest({ error: "Select at least one Resource and scope" }),
      );

    for (const [identifier, scopes] of Object.entries(grants)) {
      if (identifier === mcpResource(service.settings.baseURL))
        return yield* Effect.fail(
          new BadRequest({ error: "Administration requires OAuth access tokens, not API keys" }),
        );
      const resource = yield* service.resources.get(identifier);

      if (
        !resource ||
        !scopes.length ||
        new Set(scopes).size !== scopes.length ||
        scopes.some((scope) => !resource.scopes.includes(scope))
      )
        return yield* Effect.fail(
          new BadRequest({
            error: "Select explicitly granted, currently available Resource scopes",
          }),
        );
    }
  });

  return {
    list: Effect.fn("MachineKeys.list")(function* () {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;

      // The plugin pages in memory over one database read, so listings stop at its page size.
      const result = yield* provider(() =>
        service.auth.api.listApiKeys({
          headers,
          query: { sortBy: "createdAt", sortDirection: "asc" },
        }),
      );

      return { keys: yield* Effect.forEach(result.apiKeys, summary) };
    }),
    create: Effect.fn("MachineKeys.create")(function* (input: typeof ApiKeyInput.Type) {
      const owner = yield* CurrentOwner;
      yield* validate(input.name, input.permissions);

      const expiresIn =
        input.expiresAt === null
          ? null
          : (DateTime.toEpochMillis(input.expiresAt) - (yield* Clock.currentTimeMillis)) / 1000;

      if (expiresIn !== null && expiresIn < 1)
        return yield* Effect.fail(new BadRequest({ error: "Expiry must be in the future" }));

      const key = yield* provider(() =>
        service.auth.api.createApiKey({
          body: {
            userId: owner.userId,
            name: input.name.trim(),
            permissions: Object.fromEntries(
              Object.entries(input.permissions).map(([id, scopes]) => [id, [...scopes]]),
            ),
            expiresIn,
          },
        }),
      );

      return { ...(yield* summary(key)), key: key.key };
    }),
    update: Effect.fn("MachineKeys.update")(function* (input: typeof ApiKeyUpdate.Type) {
      const owner = yield* CurrentOwner;
      yield* validate(input.name, input.permissions);

      return yield* summary(
        yield* provider(() =>
          service.auth.api.updateApiKey({
            body: {
              userId: owner.userId,
              keyId: input.keyId,
              name: input.name?.trim(),
              enabled: input.enabled,
              permissions: input.permissions
                ? Object.fromEntries(
                    Object.entries(input.permissions).map(([id, scopes]) => [id, [...scopes]]),
                  )
                : undefined,
            },
          }),
        ),
      );
    }),
    delete: Effect.fn("MachineKeys.delete")(function* ({ keyId }: typeof ApiKeyId.Type) {
      const { providerHeaders } = yield* CurrentOwner;
      const headers = yield* providerHeaders;
      yield* provider(() => service.auth.api.deleteApiKey({ headers, body: { keyId } }));

      return { deleted: true };
    }),
    /**
     * Every enabled, unexpired key granted on the resource, with the scopes it still
     * defines, sealed and signed for offline verification. An unknown resource, and the
     * administration resource, which keys never reach, get a list with no entries.
     */
    keyList: Effect.fn("MachineKeys.keyList")(function* (identifier: string) {
      const now = yield* Clock.currentTimeMillis;
      const resource = yield* service.resources.get(identifier);

      const available =
        resource === undefined || identifier === mcpResource(service.settings.baseURL)
          ? []
          : resource.scopes;

      const rows = available.length
        ? yield* service.sql`
            SELECT id, key, referenceId, expiresAt, permissions FROM apikey
            WHERE enabled = 1 AND (expiresAt IS NULL OR expiresAt > ${new Date(now).toISOString()})
          `
        : [];

      // A row that does not decode or seal fails closed on its own: that key is left out,
      // and every other key, on every resource, is listed as before. Its digest is the
      // entry's secret, so only the key's ID reaches the log.
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
              Effect.logWarning("An API key row cannot be listed; it is left out of key lists", {
                keyId: row.id,
              }),
              [],
            ),
          ),
        ),
      );

      const iat = Math.floor(now / 1000);

      const { token } = yield* provider(() =>
        service.auth.api.signDocument({
          body: {
            typ: KeyList.type,
            payload: { aud: identifier, iat, exp: iat + KeyList.lifetime, keys: entries.flat() },
          },
        }),
      );

      return { list: token };
    }),
  };
});
