import { it } from "@effect/vitest";
import { Context, Data, Effect, Exit, Fiber, Scope } from "effect";
import { expect, vi } from "vite-plus/test";

import { Issuer } from "../../src/issuer/issuer.ts";
import { OwnerAccount } from "../../src/owner/owner.ts";
import { Database } from "../../src/platform/sqlite.ts";
import { startGeneration, testIssuer, testSettings } from "../test-issuer.ts";

class CleanupFailed extends Data.TaggedError("CleanupFailed") {}

const baseURL = "https://clankerauth.example.internal";

const createOwner = Effect.gen(function* () {
  const owners = yield* OwnerAccount;

  yield* owners.create({
    email: "owner@example.internal",
    password: "test password123",
  });
  const owner = yield* owners.find;

  if (owner === undefined) {
    return yield* Effect.die("Missing test owner");
  }

  return owner;
});

it.live.each([false, true])(
  "stopping the issuer waits for provider session cleanup (failure: %s)",
  (failCleanup) =>
    Effect.gen(function* () {
      const { context: services, scope } = yield* startGeneration();
      const owner = yield* createOwner.pipe(Effect.provideContext(services));
      const { context } = Context.get(services, Issuer);
      const { kysely } = Context.get(services, Database);
      const startedDeletion = Promise.withResolvers<undefined>();
      const allowDeletion = Promise.withResolvers<undefined>();

      const originalDelete = context.internalAdapter.deleteSession.bind(
        context.internalAdapter
      );

      vi.spyOn(context.internalAdapter, "deleteSession").mockImplementation(
        async (token) => {
          startedDeletion.resolve(undefined);
          await allowDeletion.promise;

          if (failCleanup) {
            throw new CleanupFailed();
          }

          await originalDelete(token);
        }
      );
      const destroy = vi.spyOn(kysely, "destroy");
      yield* Effect.addFinalizer(() =>
        Effect.sync(() => {
          allowDeletion.resolve(undefined);
        })
      );

      const request = yield* OwnerAccount.use((owners) =>
        Effect.scoped(
          owners.caller(owner, "owner@example.internal", true).providerHeaders
        )
      ).pipe(
        Effect.provideContext(services),
        Effect.exit,
        Effect.forkIn(scope)
      );

      yield* Effect.promise(async () => {
        await startedDeletion.promise;
      });
      const closing = yield* Effect.forkChild(Scope.close(scope, Exit.void));
      yield* Effect.sleep("50 millis");
      expect(destroy).not.toHaveBeenCalled();
      allowDeletion.resolve(undefined);
      yield* Fiber.await(request);
      yield* Fiber.join(closing);
      expect(destroy).toHaveBeenCalledOnce();
    }).pipe(Effect.provide(testSettings({ baseURL })))
);

it.live(
  "cancellation releases a temporary provider session that lasts at most one minute",
  () =>
    Effect.gen(function* () {
      const owner = yield* createOwner;
      const { context } = yield* Issuer;
      const { sql } = yield* Database;
      const deleteSession = vi.spyOn(context.internalAdapter, "deleteSession");
      const owners = yield* OwnerAccount;
      const acquired = Promise.withResolvers<undefined>();

      const before = yield* sql`SELECT id FROM session ORDER BY id`;

      const request = yield* Effect.forkChild(
        Effect.scoped(
          Effect.gen(function* () {
            yield* owners.caller(owner, "owner@example.internal", true)
              .providerHeaders;
            acquired.resolve(undefined);

            return yield* Effect.never;
          })
        )
      );

      yield* Effect.promise(async () => {
        await acquired.promise;
      });

      const sessions = yield* sql`SELECT expiresAt FROM session`;

      expect(sessions).toHaveLength(before.length + 1);
      expect(
        Date.parse(String(sessions.at(-1)?.["expiresAt"]))
      ).toBeLessThanOrEqual(Date.now() + 60_000);
      yield* Fiber.interrupt(request);
      expect(deleteSession).toHaveBeenCalledOnce();
      expect(yield* sql`SELECT id FROM session ORDER BY id`).toStrictEqual(
        before
      );
    }).pipe(Effect.provide(testIssuer({ baseURL })))
);
