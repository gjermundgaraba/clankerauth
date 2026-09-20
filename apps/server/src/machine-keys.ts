import { Clock, Effect, Schema } from "effect";
import {
  BadRequest,
  Forbidden,
  KeyPermissions,
  TooManyRequests,
  Unauthorized,
  type ApiKeyId,
  type ApiKeyInput,
  type ApiKeyUpdate,
} from "@clankerauth/api";
import type { Service } from "./auth.ts";
import { mcpResource } from "./resources.ts";
import { CurrentOwner } from "./current-owner.ts";
import { apiError, provider } from "./api-errors.ts";

const permissions = Schema.decodeUnknownSync(KeyPermissions);

const summary = (key: {
  id: string;
  name?: string | null;
  enabled: boolean;
  permissions?: unknown;
  expiresAt?: Date | null;
  createdAt: Date;
}) => ({
  keyId: key.id,
  name: key.name ?? "",
  enabled: key.enabled,
  permissions: permissions(key.permissions ?? {}),
  expiresAt: key.expiresAt?.toISOString() ?? null,
  createdAt: key.createdAt.toISOString(),
});

export function machineKeys(service: Service) {
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
      const resource = yield* service.resources.get(identifier).pipe(Effect.mapError(apiError));

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

      return { keys: result.apiKeys.map(summary) };
    }),
    create: Effect.fn("MachineKeys.create")(function* (input: typeof ApiKeyInput.Type) {
      const owner = yield* CurrentOwner;
      yield* validate(input.name, input.permissions);

      const expiresIn =
        input.expiresAt === null
          ? null
          : (Date.parse(input.expiresAt) - (yield* Clock.currentTimeMillis)) / 1000;

      if (expiresIn !== null && (!Number.isFinite(expiresIn) || expiresIn < 1))
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

      return { ...summary(key), key: key.key };
    }),
    update: Effect.fn("MachineKeys.update")(function* (input: typeof ApiKeyUpdate.Type) {
      const owner = yield* CurrentOwner;
      yield* validate(input.name, input.permissions);

      return summary(
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
    verify: Effect.fn("MachineKeys.verify")(function* (headers: Headers, identifier: string) {
      const bearer = /^Bearer (ca_[^\s]+)$/i.exec(headers.get("authorization") ?? "")?.[1];

      if (!bearer) return yield* Effect.fail(new Unauthorized({ error: "API key required" }));

      const result = yield* provider(() =>
        service.auth.api.verifyApiKey({ body: { key: bearer } }),
      );

      if (!result.valid || !result.key) {
        if (result.error?.code === "RATE_LIMITED")
          return yield* Effect.fail(
            new TooManyRequests({ error: "API key verification rate exceeded" }),
          );

        return yield* Effect.fail(new Unauthorized({ error: "Invalid API key" }));
      }

      const resource = yield* service.resources.get(identifier).pipe(Effect.mapError(apiError));
      const grants = permissions(result.key.permissions ?? {});
      const scopes = (grants[identifier] ?? []).filter((scope) => resource?.scopes.includes(scope));

      if (!resource || !scopes.length)
        return yield* Effect.fail(new Forbidden({ error: "No access to this Resource" }));

      return {
        keyId: result.key.id,
        ownerId: result.key.referenceId,
        resource: identifier,
        scopes,
        expiresAt: result.key.expiresAt?.toISOString() ?? null,
      };
    }),
  };
}
