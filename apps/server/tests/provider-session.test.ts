import { expect, test, vi } from "vite-plus/test";
import { Effect, Fiber } from "effect";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createOwner, initialize, openAuth } from "../src/auth.ts";
import { providerSession } from "../src/provider-session.ts";

test.each([false, true])(
  "shutdown waits for provider session cleanup (failure: %s)",
  async (failCleanup) => {
    const directory = mkdtempSync(join(tmpdir(), "clankerauth-provider-session-"));
    const service = await openAuth({
      baseURL: "https://auth.example.internal",
      database: join(directory, "auth.sqlite"),
      secret: randomBytes(32).toString("hex"),
      host: "127.0.0.1",
      port: 3000,
    });
    const allowDeletion = Promise.withResolvers<void>();
    let closing: Promise<void> | undefined;
    try {
      await initialize(service);
      await createOwner(service, { email: "owner@example.internal", password: "test password123" });
      const owner = await Effect.runPromise(service.owner());
      if (!owner) throw new Error("Missing test owner");
      const context = await service.auth.$context;
      const startedDeletion = Promise.withResolvers<void>();
      const originalDelete = context.internalAdapter.deleteSession.bind(context.internalAdapter);
      vi.spyOn(context.internalAdapter, "deleteSession").mockImplementation(async (token) => {
        startedDeletion.resolve();
        await allowDeletion.promise;
        if (failCleanup) throw new Error("Test cleanup failure");
        return originalDelete(token);
      });
      const destroy = vi.spyOn(service.database, "destroy");
      const request = Effect.runPromiseExit(
        Effect.scoped(providerSession(service, owner, Math.floor(Date.now() / 1000) + 300)),
      );
      await startedDeletion.promise;
      closing = service.close();
      await expect(service.run(async () => undefined)).rejects.toThrow("Service stopping");
      expect(() => service.retain()).toThrow("Service stopping");
      expect(destroy).not.toHaveBeenCalled();
      allowDeletion.resolve();
      expect((await request)._tag).toBe(failCleanup ? "Failure" : "Success");
      await closing;
      expect(destroy).toHaveBeenCalledTimes(1);
    } finally {
      allowDeletion.resolve();
      await (closing ?? service.close());
      rmSync(directory, { recursive: true, force: true });
    }
  },
);

test("cancellation releases a provider session whose lifetime is bounded by token expiry", async () => {
  const directory = mkdtempSync(join(tmpdir(), "clankerauth-provider-cancellation-"));
  const service = await openAuth({
    baseURL: "https://auth.example.internal",
    database: join(directory, "auth.sqlite"),
    secret: randomBytes(32).toString("hex"),
    host: "127.0.0.1",
    port: 3000,
  });
  let request: Fiber.Fiber<never, unknown> | undefined;
  try {
    await initialize(service);
    await createOwner(service, { email: "owner@example.internal", password: "test password123" });
    const owner = await Effect.runPromise(service.owner());
    if (!owner) throw new Error("Missing test owner");
    const context = await service.auth.$context;
    const deleteSession = vi.spyOn(context.internalAdapter, "deleteSession");
    const acquired = Promise.withResolvers<void>();
    const expiry = Math.floor(Date.now() / 1000) + 30;
    const before = await Effect.runPromise(service.sql`SELECT id FROM session ORDER BY id`);
    request = Effect.runFork(
      Effect.scoped(
        Effect.gen(function* () {
          yield* providerSession(service, owner, expiry);
          acquired.resolve();
          return yield* Effect.never;
        }),
      ),
    );
    await acquired.promise;
    const sessions = await Effect.runPromise(service.sql`SELECT expiresAt FROM session`);
    expect(sessions).toHaveLength(before.length + 1);
    expect(sessions.at(-1)?.expiresAt).toBe(new Date(expiry * 1000).toISOString());
    await Effect.runPromise(Fiber.interrupt(request));
    expect(deleteSession).toHaveBeenCalledTimes(1);
    expect(await Effect.runPromise(service.sql`SELECT id FROM session ORDER BY id`)).toEqual(
      before,
    );
  } finally {
    if (request) await Effect.runPromise(Fiber.interrupt(request));
    await service.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
