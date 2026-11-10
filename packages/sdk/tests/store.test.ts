import assert from "node:assert/strict";

import { it } from "@effect/vitest";
import { Clock, Deferred, Effect, Fiber, Logger, Result } from "effect";
import { HttpClient } from "effect/http";
import { TestClock } from "effect/testing";

import { ProviderUnavailable, Unauthorized } from "../src/errors.ts";
import { Verifier } from "../src/index.ts";
import { audience, grantOf, issuer, listIssuer } from "./support.ts";

const key = `clankerauth_${"k".repeat(64)}`;

const unknown = `clankerauth_${"u".repeat(64)}`;

const failing = [
  "Warn",
  "clankerauth key list reads are failing; a held list decides until it expires",
  { operation: "key-list.fetch" },
];

const recovered = ["Info", "clankerauth key list reads have recovered"];

const capture = (logs: Array<readonly unknown[]>) =>
  Logger.layer([
    Logger.make(({ logLevel, message }) => {
      logs.push([logLevel, ...[message].flat()]);
    }),
  ]);

const fixture = Effect.map(
  listIssuer([[key, grantOf(["read"])]]),
  ({ client, ...issued }) => ({
    ...issued,
    verifier: (store: Verifier.Store) =>
      Verifier.make({ issuer, resource: audience, store }).pipe(
        Effect.provideService(HttpClient.HttpClient, client)
      ),
  })
);

it.effect(
  "verifiers over one store share what was read: a hit reads nothing, a miss or an expiry reads and writes back",
  () =>
    Effect.gen(function* () {
      const { reads, token, verifier } = yield* fixture;
      const store = Verifier.store();
      const first = yield* verifier(store);
      yield* first.verifyToken(yield* token);
      yield* first.verifyToken(key);
      assert.deepEqual(reads, { jwks: 1, lists: 1 });

      const next = yield* verifier(store);
      yield* next.verifyToken(yield* token);
      assert.deepEqual((yield* next.verifyToken(key)).actor, {
        kind: "key",
        keyId: "key",
      });
      assert.deepEqual(reads, { jwks: 1, lists: 1 });
      assert.deepStrictEqual(structuredClone(store), store);

      const elsewhere = yield* verifier(Verifier.store());
      yield* elsewhere.verifyToken(yield* token);
      yield* elsewhere.verifyToken(key);
      assert.deepEqual(reads, { jwks: 2, lists: 2 });

      yield* TestClock.adjust("1 minute");
      const later = yield* verifier(store);
      yield* later.verifyToken(yield* token);
      yield* later.verifyToken(key);
      assert.deepEqual(reads, { jwks: 3, lists: 3 });
      const now = yield* Clock.currentTimeMillis;
      assert.equal(store.jwks.get(issuer)?.readAt, now);

      yield* TestClock.adjust("5 seconds");
      yield* (yield* verifier(store)).verifyToken(key);
      assert.deepEqual(reads, { jwks: 3, lists: 3 });
    })
);

it.effect("concurrent misses each read, and every one of them verifies", () =>
  Effect.gen(function* () {
    const { reads, upstream, token, verifier } = yield* fixture;
    const store = Verifier.store();
    const jwt = yield* token;

    const together = (credential: string) =>
      Effect.gen(function* () {
        const hold = yield* Deferred.make<undefined>();
        upstream.hold = hold;

        const fiber = yield* Effect.forEach(
          [1, 2],
          () =>
            Effect.flatMap(verifier(store), (each) =>
              each.verifyToken(credential)
            ),
          { concurrency: "unbounded" }
        ).pipe(Effect.forkChild);

        yield* TestClock.withLive(Effect.sleep("100 millis"));
        const started = { ...reads };
        upstream.hold = undefined;
        yield* Deferred.succeed(hold, undefined);
        yield* Fiber.join(fiber);

        return started;
      });

    assert.deepEqual(yield* together(jwt), { jwks: 2, lists: 0 });
    assert.deepEqual(yield* together(key), { jwks: 2, lists: 2 });
    assert.deepEqual(reads, { jwks: 2, lists: 2 });

    yield* (yield* verifier(store)).verifyToken(jwt);
    yield* (yield* verifier(store)).verifyToken(key);
    assert.deepEqual(reads, { jwks: 2, lists: 2 });
  })
);

it.effect.each(["slow read fails", "fast read fails"] as const)(
  "when concurrent reads race, a success stands in the store: %s",
  (order) => {
    const logs: Array<readonly unknown[]> = [];

    return Effect.gen(function* () {
      const { reads, upstream, token, verifier } = yield* fixture;
      const store = Verifier.store();
      const jwt = yield* token;
      const slowFails = order === "slow read fails";

      const verify = (credential: string) =>
        Effect.result(
          Effect.flatMap(verifier(store), (each) =>
            each.verifyToken(credential)
          )
        );

      for (const credential of [jwt, key]) {
        const hold = yield* Deferred.make<undefined>();
        upstream.unavailable = slowFails;
        upstream.hold = hold;
        const slow = yield* verify(credential).pipe(Effect.forkChild);
        yield* TestClock.withLive(Effect.sleep("100 millis"));

        upstream.unavailable = !slowFails;
        upstream.hold = undefined;
        const fast = yield* verify(credential);
        yield* Deferred.succeed(hold, undefined);
        const late = yield* Fiber.join(slow);
        assert.equal(Result.isSuccess(fast), slowFails);

        assert.equal(Result.isSuccess(late), !slowFails || credential === key);
      }

      assert.deepEqual(reads, { jwks: 2, lists: 2 });
      assert.equal(
        store.keyLists.get(JSON.stringify([issuer, audience]))?.failure,
        undefined
      );
      assert.ok(Result.isSuccess(yield* verify(jwt)));
      assert.ok(Result.isSuccess(yield* verify(key)));
      assert.deepEqual(reads, { jwks: 2, lists: 2 });
      assert.deepEqual(logs, slowFails ? [] : [failing, recovered]);
    }).pipe(Effect.provide(capture(logs)));
  }
);

it.effect(
  "an outage is ProviderUnavailable without a held list; with one, it decides until expiry and warns once",
  () => {
    const logs: Array<readonly unknown[]> = [];

    return Effect.gen(function* () {
      const { reads, upstream, token, verifier } = yield* fixture;
      const store = Verifier.store();

      const verify = (credential: string) =>
        Effect.flatMap(verifier(store), (each) => each.verifyToken(credential));

      const refused = (credential: string) => Effect.flip(verify(credential));

      upstream.unavailable = true;
      const jwt = yield* token;
      const cold = yield* refused(key);
      assert.ok(cold instanceof ProviderUnavailable);
      assert.equal(cold.operation, "key-list.fetch");
      const unsigned = yield* refused(jwt);
      assert.ok(unsigned instanceof ProviderUnavailable);
      assert.equal(unsigned.operation, "jwks.fetch");
      const cooling = yield* refused(key);
      assert.ok(cooling instanceof ProviderUnavailable);
      assert.equal(cooling.operation, "key-list.fetch");
      assert.deepEqual(reads, { jwks: 1, lists: 1 });

      upstream.unavailable = false;
      yield* TestClock.adjust("5 seconds");
      yield* verify(key);
      yield* verify(jwt);
      assert.deepEqual(reads, { jwks: 2, lists: 2 });

      upstream.unavailable = true;
      yield* TestClock.adjust("1 minute");
      assert.deepEqual((yield* verify(key)).actor, {
        kind: "key",
        keyId: "key",
      });
      assert.ok((yield* refused(unknown)) instanceof Unauthorized);
      assert.ok((yield* refused(jwt)) instanceof ProviderUnavailable);
      assert.deepEqual(reads, { jwks: 3, lists: 3 });

      yield* TestClock.adjust("5 seconds");
      yield* verify(key);
      assert.equal(reads.lists, 4);

      upstream.unavailable = false;
      yield* TestClock.adjust("5 seconds");
      yield* verify(key);
      yield* TestClock.adjust("1 minute");
      yield* verify(key);
      assert.equal(reads.lists, 6);
      assert.deepEqual(logs, [failing, recovered, failing, recovered]);
    }).pipe(Effect.provide(capture(logs)));
  }
);

it.effect(
  "a key list read runs its list and JWKS fetches together on deadlines of their own, so a stalled JWKS is decided by the held list",
  () =>
    Effect.gen(function* () {
      const { reads, upstream, verifier } = yield* fixture;
      const store = Verifier.store();

      const verify = Effect.flatMap(verifier(store), (each) =>
        each.verifyToken(key)
      );

      upstream.latency = { lists: "1 second", jwks: "2500 millis" };
      const cold = yield* verify.pipe(Effect.forkChild);
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      yield* TestClock.adjust("1 second");
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      yield* TestClock.adjust("2500 millis");
      assert.deepEqual((yield* Fiber.join(cold)).actor, {
        kind: "key",
        keyId: "key",
      });
      assert.deepEqual(reads, { jwks: 1, lists: 1 });

      upstream.latency = { lists: "2500 millis", jwks: "1 minute" };
      yield* TestClock.adjust("1 minute");
      const stalled = yield* verify.pipe(Effect.forkChild);
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      yield* TestClock.adjust("2500 millis");
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      yield* TestClock.adjust("500 millis");
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      assert.notEqual(stalled.pollUnsafe(), undefined);
      assert.deepEqual((yield* Fiber.join(stalled)).actor, {
        kind: "key",
        keyId: "key",
      });
      assert.equal(
        store.keyLists.get(JSON.stringify([issuer, audience]))?.failure,
        "jwks.timeout"
      );
    })
);
