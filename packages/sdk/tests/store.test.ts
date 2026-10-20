import assert from "node:assert/strict";
import { it } from "@effect/vitest";
import { Clock, Deferred, Effect, Fiber, Logger, Result } from "effect";
import { HttpClient, HttpClientResponse } from "effect/http";
import { TestClock } from "effect/testing";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { ProviderUnavailable, Unauthorized } from "../src/errors.ts";
import { Verifier } from "../src/index.ts";
import { signList } from "./support.ts";

const issuer = "https://issuer.example/api/auth";

const resource = "https://notes.example/";

const key = `clankerauth_${"k".repeat(64)}`;

const unknown = `clankerauth_${"u".repeat(64)}`;

/**
 * How the stub issuer answers a read: failing, if it is unavailable when the read arrives, and
 * after `hold` completes, if one is set then.
 */
interface Upstream {
  unavailable: boolean;
  hold: Deferred.Deferred<void> | undefined;
}

const fixture = Effect.gen(function* () {
  const pair = yield* Effect.promise(() => generateKeyPair("EdDSA"));

  const jwk = {
    ...(yield* Effect.promise(() => exportJWK(pair.publicKey))),
    kid: "fixture",
    alg: "EdDSA",
  };

  const reads = { jwks: 0, lists: 0 };

  const issuerState: Upstream = {
    unavailable: false,
    hold: undefined,
  };

  const client = HttpClient.make((request) =>
    Effect.gen(function* () {
      const jwks = request.url.endsWith("/jwks");

      if (jwks) reads.jwks++;
      else reads.lists++;
      const { unavailable, hold } = issuerState;

      if (hold !== undefined) yield* Deferred.await(hold);

      if (unavailable)
        return HttpClientResponse.fromWeb(request, new Response("{}", { status: 503 }));

      if (jwks) return HttpClientResponse.fromWeb(request, Response.json({ keys: [jwk] }));
      const seconds = Math.floor((yield* Clock.currentTimeMillis) / 1000);

      const list = yield* Effect.promise(() =>
        signList(
          pair.privateKey,
          issuer,
          resource,
          [[key, { keyId: "key", ownerId: "owner", scopes: ["read"], expiresAt: null }]],
          seconds,
        ),
      );

      return HttpClientResponse.fromWeb(request, Response.json({ list }));
    }),
  );

  const token = Effect.flatMap(Clock.currentTimeMillis, (now) =>
    Effect.promise(() =>
      new SignJWT({ client_id: "web", scope: "read" })
        .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid: "fixture" })
        .setIssuer(issuer)
        .setAudience(resource)
        .setSubject("owner")
        .setIssuedAt(Math.floor(now / 1000))
        .setExpirationTime(Math.floor(now / 1000) + 3600)
        .sign(pair.privateKey),
    ),
  );

  const verifier = (store: Verifier.Store) =>
    Verifier.make({ issuer, resource, store }).pipe(
      Effect.provideService(HttpClient.HttpClient, client),
    );

  return { reads, issuer: issuerState, token, verifier };
});

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
      assert.deepEqual((yield* next.verifyToken(key)).actor, { kind: "key", keyId: "key" });
      assert.deepEqual(reads, { jwks: 1, lists: 1 });
      // why: a clone keeps only plain data, so an Effect, Promise, Response or class instance fails.
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
      assert.equal(store.keyLists.get(JSON.stringify([issuer, resource]))?.held?.readAt, now);

      yield* (yield* verifier(store)).verifyToken(key);
      assert.deepEqual(reads, { jwks: 3, lists: 3 });
    }),
);

it.effect("concurrent misses each read, and every one of them verifies", () =>
  Effect.gen(function* () {
    const { reads, issuer: upstream, token, verifier } = yield* fixture;
    const store = Verifier.store();
    const jwt = yield* token;

    const together = (credential: string) =>
      Effect.gen(function* () {
        const hold = yield* Deferred.make<void>();
        upstream.hold = hold;

        const fiber = yield* Effect.all(
          [1, 2].map(() => Effect.flatMap(verifier(store), (each) => each.verifyToken(credential))),
          { concurrency: "unbounded" },
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
  }),
);

it.effect("a read that fails after a concurrent one succeeded leaves the success standing", () => {
  const logs: Array<readonly unknown[]> = [];

  const capture = Logger.make(({ logLevel, message }) => {
    logs.push([logLevel, ...[message].flat()]);
  });

  return Effect.gen(function* () {
    const { reads, issuer: upstream, token, verifier } = yield* fixture;
    const store = Verifier.store();
    const jwt = yield* token;

    const verify = (credential: string) =>
      Effect.flatMap(verifier(store), (each) => each.verifyToken(credential));

    for (const credential of [jwt, key]) {
      const hold = yield* Deferred.make<void>();
      upstream.unavailable = true;
      upstream.hold = hold;
      const slow = yield* Effect.result(verify(credential)).pipe(Effect.forkChild);
      yield* TestClock.withLive(Effect.sleep("100 millis"));

      upstream.unavailable = false;
      upstream.hold = undefined;
      yield* verify(credential);
      yield* Deferred.succeed(hold, undefined);
      const late = yield* Fiber.join(slow);

      // why: the list the concurrent read wrote decides for the key; JWKS has no held fallback.
      if (credential === key) assert(Result.isSuccess(late));
      else assert(Result.isFailure(late) && late.failure instanceof ProviderUnavailable);
    }

    assert.deepEqual(reads, { jwks: 2, lists: 2 });
    const settled = store.jwks.get(issuer);
    assert(settled !== undefined && "keys" in settled);
    assert.equal(store.keyLists.get(JSON.stringify([issuer, resource]))?.failure, undefined);
    yield* verify(jwt);
    yield* verify(key);
    assert.deepEqual(reads, { jwks: 2, lists: 2 });
    assert.deepEqual(logs, []);
  }).pipe(Effect.provide(Logger.layer([capture])));
});

it.effect(
  "an outage is ProviderUnavailable without a held list; with one, it decides until expiry and warns once",
  () => {
    const logs: Array<readonly unknown[]> = [];

    const capture = Logger.make(({ logLevel, message }) => {
      logs.push([logLevel, ...[message].flat()]);
    });

    return Effect.gen(function* () {
      const { reads, issuer: upstream, token, verifier } = yield* fixture;
      const store = Verifier.store();

      const verify = (credential: string) =>
        Effect.flatMap(verifier(store), (each) => each.verifyToken(credential));

      const refused = (credential: string) => Effect.flip(verify(credential));

      upstream.unavailable = true;
      const jwt = yield* token;
      const cold = yield* refused(key);
      assert(cold instanceof ProviderUnavailable);
      assert.equal(cold.operation, "key-list.fetch");
      const unsigned = yield* refused(jwt);
      assert(unsigned instanceof ProviderUnavailable);
      assert.equal(unsigned.operation, "jwks.fetch");
      const cooling = yield* refused(key);
      assert(cooling instanceof ProviderUnavailable);
      assert.equal(cooling.operation, "key-list.fetch");
      assert.deepEqual(reads, { jwks: 1, lists: 1 });

      upstream.unavailable = false;
      yield* TestClock.adjust("5 seconds");
      yield* verify(key);
      yield* verify(jwt);
      assert.deepEqual(reads, { jwks: 2, lists: 2 });

      upstream.unavailable = true;
      yield* TestClock.adjust("1 minute");
      assert.deepEqual((yield* verify(key)).actor, { kind: "key", keyId: "key" });
      assert((yield* refused(unknown)) instanceof Unauthorized);
      assert((yield* refused(jwt)) instanceof ProviderUnavailable);
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

      const failing = [
        "Warn",
        "clankerauth key list reads are failing; a held list decides until it expires",
        { operation: "key-list.fetch" },
      ];

      const recovered = ["Info", "clankerauth key list reads have recovered"];
      assert.deepEqual(logs, [failing, recovered, failing, recovered]);
    }).pipe(Effect.provide(Logger.layer([capture])));
  },
);
