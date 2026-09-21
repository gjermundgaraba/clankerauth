import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import { Deferred, Effect, Fiber, Layer, Schema } from "effect";
import { HttpClientError, TransportError } from "effect/unstable/http/HttpClientError";
import { TestClock } from "effect/testing";
import {
  HttpClient,
  HttpClientRequest,
  HttpClientResponse,
  HttpRouter,
  HttpServer,
  HttpServerResponse,
} from "effect/unstable/http";
import { authenticationErrors, ProviderUnavailable, Unauthorized } from "../src/errors.ts";
import { Resource } from "../src/effect-actions.ts";

test("verification deadlines interrupt the supplied HTTP transport", () =>
  Effect.runPromise(
    Effect.gen(function* () {
      const started = yield* Deferred.make<void>();
      const cancelled = yield* Deferred.make<void>();

      const client = HttpClient.make(() =>
        Effect.gen(function* () {
          yield* Deferred.succeed(started, undefined);

          return yield* Effect.never.pipe(Effect.ensuring(Deferred.succeed(cancelled, undefined)));
        }),
      );

      const resource = yield* Resource.make({
        issuer: "https://issuer.example/api/auth",
        publicUrl: new URL("https://notes.example"),
        scopes: { read: "notes:read" },
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const fiber = yield* Effect.flip(resource.verifier.verifyToken("ca_test")).pipe(
        Effect.forkChild,
      );

      yield* Deferred.await(started);
      yield* TestClock.adjust("5 seconds");
      const error = yield* Fiber.join(fiber);
      assert(error instanceof ProviderUnavailable);
      assert.equal(error.operation, "verify.timeout");
      yield* Deferred.await(cancelled);
    }).pipe(Effect.provide(TestClock.layer())),
  ));

test("JWKS lookups refresh unknown keys once per cooldown, expire normally, and retry initial outages", async () => {
  const { exportJWK, generateKeyPair, SignJWT } = await import("jose");
  const first = await generateKeyPair("EdDSA");
  const second = await generateKeyPair("EdDSA");
  const firstKey = { ...(await exportJWK(first.publicKey)), kid: "first", alg: "EdDSA" };
  const secondKey = { ...(await exportJWK(second.publicKey)), kid: "second", alg: "EdDSA" };
  const issuer = "https://issuer.example/api/auth";
  const audience = "https://notes.example/";

  const sign = (kid: string, key: CryptoKey) =>
    new SignJWT({ client_id: "web", scope: "read" })
      .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject("owner")
      .setIssuedAt(0)
      .setExpirationTime(2000)
      .sign(key);

  const firstToken = await sign("first", first.privateKey);
  const secondToken = await sign("second", second.privateKey);
  await Effect.runPromise(
    Effect.gen(function* () {
      let reads = 0;
      let unavailable = true;
      let key = firstKey;
      let paused = false;
      let started = yield* Deferred.make<void>();
      let release = yield* Deferred.make<void>();

      const client = HttpClient.make((request) =>
        Effect.gen(function* () {
          reads++;

          if (paused) {
            yield* Deferred.succeed(started, undefined);
            yield* Deferred.await(release);
          }

          return HttpClientResponse.fromWeb(
            request,
            Response.json({ keys: [key] }, { status: unavailable ? 503 : 200 }),
          );
        }),
      );

      const resource = yield* Resource.make({
        issuer,
        publicUrl: new URL(audience),
        scopes: { read: "read" },
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const verify = resource.verifier.verifyToken;
      assert((yield* Effect.flip(verify(firstToken))) instanceof ProviderUnavailable);
      unavailable = false;
      yield* Effect.all([verify(firstToken), verify(firstToken), verify(firstToken)], {
        concurrency: "unbounded",
      });
      assert.equal(reads, 2);
      key = secondKey;
      const missing = yield* Effect.flip(verify(secondToken));
      assert(missing instanceof Unauthorized);
      assert.equal(reads, 2);
      yield* TestClock.adjust("30 seconds");
      paused = true;

      const refreshing = yield* Effect.all(
        [verify(secondToken), verify(secondToken), verify(secondToken)],
        {
          concurrency: "unbounded",
        },
      ).pipe(Effect.forkChild);

      yield* Deferred.await(started);
      // Known keys remain usable even while a refresh is waiting on the provider.
      yield* verify(firstToken);
      paused = false;
      yield* Deferred.succeed(release, undefined);
      yield* Fiber.join(refreshing);
      assert.equal(reads, 3);
      assert((yield* Effect.flip(verify(firstToken))) instanceof Unauthorized);
      assert.equal(reads, 3);
      yield* TestClock.adjust("30 seconds");
      unavailable = true;

      const failures = yield* Effect.all(
        Array.from({ length: 3 }, () => Effect.flip(verify(firstToken))),
        { concurrency: "unbounded" },
      );

      assert(failures.every((error) => error instanceof ProviderUnavailable));
      assert.equal(reads, 4);
      yield* verify(secondToken);
      assert.equal(reads, 4);
      unavailable = false;
      yield* TestClock.adjust("30 seconds");
      assert((yield* Effect.flip(verify(firstToken))) instanceof Unauthorized);
      assert.equal(reads, 5);
      assert((yield* Effect.flip(verify(firstToken))) instanceof Unauthorized);
      assert.equal(reads, 5);
      yield* TestClock.adjust("10 minutes");
      yield* verify(secondToken);
      assert.equal(reads, 6);
      yield* TestClock.adjust("30 seconds");
      key = firstKey;
      paused = true;
      started = yield* Deferred.make<void>();
      release = yield* Deferred.make<void>();
      const timed = yield* Effect.flip(verify(firstToken)).pipe(Effect.forkChild);
      yield* Deferred.await(started);
      yield* TestClock.adjust("5 seconds");
      const timeout = yield* Fiber.join(timed);
      assert(timeout instanceof ProviderUnavailable);
      assert.equal(timeout.operation, "verify.timeout");
      paused = false;
      yield* verify(secondToken);
      assert((yield* Effect.flip(verify(firstToken))) instanceof ProviderUnavailable);
      assert.equal(reads, 7);
      yield* TestClock.adjust("25 seconds");
      yield* verify(firstToken);
      assert.equal(reads, 8);
    }).pipe(Effect.provide(TestClock.layer())),
  );
});

test("diagnostic causes survive adapters but never enter public error schemas or HTTP bodies", () =>
  Effect.runPromise(
    Effect.gen(function* () {
      const secret = "private-provider-diagnostic";
      const request = HttpClientRequest.get("https://issuer.example/jwks");

      const transportCause = new HttpClientError({
        reason: new TransportError({ request, cause: new Error(secret) }),
      });

      const client = HttpClient.make(() => Effect.fail(transportCause));

      const resource = yield* Resource.make({
        issuer: "https://issuer.example",
        publicUrl: new URL("https://notes.example"),
        scopes: { read: "notes:read" },
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const failure = yield* Effect.flip(resource.verifier.verifyToken("ca_test"));
      assert(failure instanceof ProviderUnavailable);
      assert.equal(failure.cause, transportCause);

      const error = new Unauthorized({ message: "Sign in required", cause: { secret } });
      const encoded = Schema.encodeSync(Schema.Union(authenticationErrors))(error);
      assert(!("cause" in encoded));
      assert(!JSON.stringify(encoded).includes(secret));
      assert(!JSON.stringify(error).includes(secret));

      const web = HttpRouter.toWebHandler(
        HttpRouter.add("GET", "/private", Effect.succeed(HttpServerResponse.empty())).pipe(
          Layer.provide(Resource.middleware(resource).layer),
          Layer.provide(HttpServer.layerServices),
        ),
      );

      yield* Effect.promise(async () => {
        try {
          const response = await web.handler(
            new Request("https://notes.example/private", {
              headers: { authorization: "Bearer ca_test" },
            }),
          );

          assert.equal(response.status, 503);
          assert.deepEqual(
            await response.json(),
            Schema.encodeSync(ProviderUnavailable)(
              new ProviderUnavailable({ operation: "http.request" }),
            ),
          );
        } finally {
          await web.dispose();
        }
      });
    }),
  ));
