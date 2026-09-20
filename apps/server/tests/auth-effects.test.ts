import { expect, test } from "vite-plus/test";
import { Effect, Redacted } from "effect";
import { TestClock } from "effect/testing";
import { initialize, openAuth } from "../src/auth.ts";

test("abandoned-client cleanup keeps a client at exactly seven days and removes it one millisecond later", () =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const now = 1_000_000_000_000;
        const week = 7 * 24 * 60 * 60 * 1000;
        yield* TestClock.setTime(now);

        const service = yield* Effect.acquireRelease(
          openAuth({
            baseURL: "https://issuer.example",
            secret: Redacted.make("test-only-secret-with-at-least-32-characters"),
            database: ":memory:",
            host: "127.0.0.1",
            port: 3000,
          }),
          (service) => Effect.promise(() => service.close()),
        );

        yield* initialize(service);
        // An unowned insert is an automatic client; the provenance trigger onboards it.
        yield* service.sql`INSERT INTO oauthClient (id, clientId, redirectUris, createdAt, updatedAt)
          VALUES ('stale', 'stale', '[]', ${now - week}, ${now - week})`;

        const remaining = () =>
          service.sql`SELECT clientId FROM clientOnboarding WHERE clientId = 'stale'`;

        yield* service.onboarding.cleanup();
        expect(yield* remaining()).toEqual([{ clientId: "stale" }]);
        yield* TestClock.adjust("1 millis");
        yield* service.onboarding.cleanup();
        expect(yield* remaining()).toEqual([]);
        expect(
          yield* service.sql`SELECT clientId FROM oauthClient WHERE clientId = 'stale'`,
        ).toEqual([]);
      }),
    ).pipe(Effect.provide(TestClock.layer())),
  ));
