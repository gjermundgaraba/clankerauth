import { expect, test, vi } from "vite-plus/test";
import { Effect, Fiber } from "effect";
import { createOwner } from "../src/auth.ts";
import { openIssuer } from "./issuer.ts";
import { providerSession } from "../src/provider-session.ts";

test.each([false, true])(
  "stopping the issuer waits for provider session cleanup (failure: %s)",
  async (failCleanup) => {
    const issuer = await openIssuer({ baseURL: "https://auth.example.internal" });
    const { service } = issuer;
    const allowDeletion = Promise.withResolvers<void>();
    let closing: Promise<void> | undefined;

    try {
      await issuer.run(
        createOwner(issuer.service, {
          email: "owner@example.internal",
          password: "test password123",
        }),
      );
      const owner = await Effect.runPromise(service.owner());

      if (!owner) throw new Error("Missing test owner");
      const { context } = service;
      const startedDeletion = Promise.withResolvers<void>();
      const originalDelete = context.internalAdapter.deleteSession.bind(context.internalAdapter);
      vi.spyOn(context.internalAdapter, "deleteSession").mockImplementation(async (token) => {
        startedDeletion.resolve();
        await allowDeletion.promise;

        if (failCleanup) throw new Error("Test cleanup failure");

        return originalDelete(token);
      });
      const destroy = vi.spyOn(service.database, "destroy");
      const request = issuer.runExit(Effect.scoped(providerSession(issuer.service, owner)));

      await startedDeletion.promise;
      closing = issuer.stop();
      await new Promise((resolve) => setTimeout(resolve, 50));
      // The request fiber is owned by the scope shutting down, ahead of the database.
      expect(destroy).not.toHaveBeenCalled();
      allowDeletion.resolve();
      await request;
      await closing;
      expect(destroy).toHaveBeenCalledTimes(1);
    } finally {
      allowDeletion.resolve();
      await (closing ?? Promise.resolve());
      await issuer.close();
    }
  },
);

test("cancellation releases a temporary provider session that lasts at most one minute", async () => {
  const issuer = await openIssuer({ baseURL: "https://auth.example.internal" });
  const { service } = issuer;
  let request: Fiber.Fiber<never, unknown> | undefined;

  try {
    await issuer.run(
      createOwner(issuer.service, {
        email: "owner@example.internal",
        password: "test password123",
      }),
    );
    const owner = await Effect.runPromise(service.owner());

    if (!owner) throw new Error("Missing test owner");
    const { context } = service;
    const deleteSession = vi.spyOn(context.internalAdapter, "deleteSession");
    const acquired = Promise.withResolvers<void>();
    const before = await Effect.runPromise(service.sql`SELECT id FROM session ORDER BY id`);

    request = issuer.runFork(
      Effect.scoped(
        Effect.gen(function* () {
          yield* providerSession(issuer.service, owner);
          acquired.resolve();

          return yield* Effect.never;
        }),
      ),
    );
    await acquired.promise;
    const sessions = await Effect.runPromise(service.sql`SELECT expiresAt FROM session`);
    expect(sessions).toHaveLength(before.length + 1);
    expect(Date.parse(String(sessions.at(-1)?.expiresAt))).toBeLessThanOrEqual(Date.now() + 60_000);
    await Effect.runPromise(Fiber.interrupt(request));
    expect(deleteSession).toHaveBeenCalledTimes(1);
    expect(await Effect.runPromise(service.sql`SELECT id FROM session ORDER BY id`)).toEqual(
      before,
    );
  } finally {
    if (request) await Effect.runPromise(Fiber.interrupt(request));
    await issuer.close();
  }
});
