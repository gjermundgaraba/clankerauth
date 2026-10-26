import { it } from "@effect/vitest";
import { expect, vi } from "vite-plus/test";
import { Context, Effect, Exit, Fiber, Scope } from "effect";
import { startGeneration, testIssuer, testSettings } from "../test-issuer.ts";
import { Database } from "../../src/platform/sqlite.ts";
import { OwnerAccount } from "../../src/owner/owner.ts";
import { Issuer } from "../../src/issuer/issuer.ts";

const baseURL = "https://clankerauth.example.internal";

const createOwner = Effect.gen(function* () {
  const owners = yield* OwnerAccount;

  yield* owners.create({ email: "owner@example.internal", password: "test password123" });
  const owner = yield* owners.find();

  if (!owner) return yield* Effect.die("Missing test owner");

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
      const startedDeletion = Promise.withResolvers<void>();
      const allowDeletion = Promise.withResolvers<void>();
      const originalDelete = context.internalAdapter.deleteSession.bind(context.internalAdapter);
      vi.spyOn(context.internalAdapter, "deleteSession").mockImplementation(async (token) => {
        startedDeletion.resolve();
        await allowDeletion.promise;

        if (failCleanup) throw new Error("Test cleanup failure");

        return originalDelete(token);
      });
      const destroy = vi.spyOn(kysely, "destroy");
      yield* Effect.addFinalizer(() => Effect.sync(() => allowDeletion.resolve()));

      const request = yield* OwnerAccount.use((owners) =>
        Effect.scoped(owners.caller(owner, "owner@example.internal", true).providerHeaders),
      ).pipe(Effect.provideContext(services), Effect.exit, Effect.forkIn(scope));

      yield* Effect.promise(() => startedDeletion.promise);
      const closing = yield* Effect.forkChild(Scope.close(scope, Exit.void));
      yield* Effect.sleep("50 millis");
      expect(destroy).not.toHaveBeenCalled();
      allowDeletion.resolve();
      yield* Fiber.await(request);
      yield* Fiber.join(closing);
      expect(destroy).toHaveBeenCalledTimes(1);
    }).pipe(Effect.provide(testSettings({ baseURL }))),
);

it.live("cancellation releases a temporary provider session that lasts at most one minute", () =>
  Effect.gen(function* () {
    const owner = yield* createOwner;
    const { context } = yield* Issuer;
    const { sql } = yield* Database;
    const deleteSession = vi.spyOn(context.internalAdapter, "deleteSession");
    const owners = yield* OwnerAccount;
    const acquired = Promise.withResolvers<void>();

    const before = yield* sql`SELECT id FROM session ORDER BY id`;

    const request = yield* Effect.forkChild(
      Effect.scoped(
        Effect.gen(function* () {
          yield* owners.caller(owner, "owner@example.internal", true).providerHeaders;
          acquired.resolve();

          return yield* Effect.never;
        }),
      ),
    );

    yield* Effect.promise(() => acquired.promise);

    const sessions = yield* sql`SELECT expiresAt FROM session`;

    expect(sessions).toHaveLength(before.length + 1);
    expect(Date.parse(String(sessions.at(-1)?.["expiresAt"]))).toBeLessThanOrEqual(
      Date.now() + 60_000,
    );
    yield* Fiber.interrupt(request);
    expect(deleteSession).toHaveBeenCalledTimes(1);
    expect(yield* sql`SELECT id FROM session ORDER BY id`).toEqual(before);
  }).pipe(Effect.provide(testIssuer({ baseURL }))),
);
