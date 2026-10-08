import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import { Clock, Deferred, Effect, Fiber, Layer, Schema } from "effect";
import { HttpClientError, TransportError } from "effect/http/HttpClientError";
import { TestClock } from "effect/testing";
import {
  HttpClient,
  HttpClientRequest,
  HttpClientResponse,
  HttpRouter,
  HttpServer,
  HttpServerResponse,
} from "effect/http";
import { ProviderUnavailable, Unauthorized } from "../src/errors.ts";
import * as KeyList from "../src/key-list.ts";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { CurrentPrincipal } from "../src/session.ts";
import { Login, Notes, resourceOf, sent, signList } from "./support.ts";

/** What a key list test signs with and publishes, for one resource. */
const listIssuer = async () => {
  const { exportJWK, generateKeyPair } = await import("jose");
  const pair = await generateKeyPair("EdDSA");

  return {
    pair,
    jwk: { ...(await exportJWK(pair.publicKey)), kid: "fixture", alg: "EdDSA" },
    issuer: "https://issuer.example/api/auth",
    audience: "https://notes.example/",
  };
};

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

      const resource = yield* resourceOf({
        issuer: "https://issuer.example/api/auth",
        publicUrl: new URL("https://notes.example"),
        scopes: ["notes:read"],
        required: "notes:read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      // A token that names its key, so verification must read JWKS.
      const header = Buffer.from(JSON.stringify({ alg: "EdDSA", kid: "k", typ: "at+jwt" }));
      const token = `${header.toString("base64url")}.e30.AA`;

      const fiber = yield* Effect.flip(resource.verifier.verifyToken(token)).pipe(Effect.forkChild);

      yield* Deferred.await(started);
      yield* TestClock.adjust("5 seconds");
      const error = yield* Fiber.join(fiber);
      assert(error instanceof ProviderUnavailable);
      assert.equal(error.operation, "verify.timeout");
      yield* Deferred.await(cancelled);
    }).pipe(Effect.provide(TestClock.layer())),
  ));

test("one JWKS read serves every key until it expires, a failed one cools down, and an abandoned one is dropped", async () => {
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
      const started = yield* Deferred.make<void>();

      const client = HttpClient.make((request) =>
        Effect.gen(function* () {
          reads++;

          if (paused) {
            yield* Deferred.succeed(started, undefined);

            return yield* Effect.never;
          }

          return HttpClientResponse.fromWeb(
            request,
            Response.json({ keys: [key] }, { status: unavailable ? 503 : 200 }),
          );
        }),
      );

      const resource = yield* resourceOf({
        issuer,
        publicUrl: new URL(audience),
        scopes: ["read"],
        required: "read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const verify = resource.verifier.verifyToken;

      // An unreachable issuer is an outage, and the cooldown holds off the next read.
      assert((yield* Effect.flip(verify(firstToken))) instanceof ProviderUnavailable);
      assert((yield* Effect.flip(verify(firstToken))) instanceof ProviderUnavailable);
      assert.equal(reads, 1);
      unavailable = false;
      yield* TestClock.adjust("5 seconds");

      // Concurrent verifications share a single read.
      yield* Effect.all([verify(firstToken), verify(firstToken), verify(firstToken)], {
        concurrency: "unbounded",
      });
      assert.equal(reads, 2);

      // An identifier the document does not publish is refused, never chased.
      key = secondKey;
      assert((yield* Effect.flip(verify(secondToken))) instanceof Unauthorized);
      assert.equal(reads, 2);

      // The next read rotates the new key in and the old one out.
      yield* TestClock.adjust("1 minute");
      yield* verify(secondToken);
      assert((yield* Effect.flip(verify(firstToken))) instanceof Unauthorized);
      assert.equal(reads, 3);

      // A read its only caller gave up on is dropped, not held: the next caller reads
      // again, with a deadline of its own, and that read is held as any other.
      yield* TestClock.adjust("1 minute");
      paused = true;
      const abandoned = yield* verify(secondToken).pipe(Effect.forkChild);
      yield* Deferred.await(started);
      yield* TestClock.adjust("5 seconds");
      const timeout = yield* Effect.flip(Fiber.join(abandoned));
      assert(timeout instanceof ProviderUnavailable);
      assert.equal(timeout.operation, "verify.timeout");
      paused = false;
      yield* verify(secondToken);
      assert.equal(reads, 5);
      yield* TestClock.adjust("5 seconds");
      yield* verify(secondToken);
      assert.equal(reads, 5);
    }).pipe(Effect.provide(TestClock.layer())),
  );
});

test("a key list refreshes every minute and outlasts an outage for its lifetime", async () => {
  const { pair, jwk, issuer, audience } = await listIssuer();
  const key = `clankerauth_${"k".repeat(64)}`;
  const reader = `clankerauth_${"r".repeat(64)}`;

  const grant = (scopes: string[], expiresAt: number | null = null) => ({
    keyId: "key",
    ownerId: "owner",
    scopes,
    expiresAt,
  });

  await Effect.runPromise(
    Effect.gen(function* () {
      let lists = 0;
      let unavailable = false;
      let stalled = false;

      const granted = new Map([
        [key, grant(["read", "write"])],
        [reader, grant(["read"])],
      ]);

      const client = HttpClient.make((request) =>
        Effect.gen(function* () {
          if (stalled) return yield* Effect.never;

          if (unavailable)
            return HttpClientResponse.fromWeb(request, new Response("{}", { status: 503 }));

          if (request.url.endsWith("/jwks"))
            return HttpClientResponse.fromWeb(request, Response.json({ keys: [jwk] }));
          lists++;
          const seconds = Math.floor((yield* Clock.currentTimeMillis) / 1000);

          const list = yield* Effect.promise(() =>
            signList(pair.privateKey, issuer, audience, new Map(granted), seconds),
          );

          return HttpClientResponse.fromWeb(request, Response.json({ list }));
        }),
      );

      const resource = yield* resourceOf({
        issuer,
        publicUrl: new URL(audience),
        scopes: ["read", "write"],
        required: "read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const verify = resource.verifier.verifyToken;
      yield* TestClock.adjust("1 minute");
      assert.deepEqual((yield* verify(key)).actor, { kind: "key", keyId: "key" });

      // A socket admitted for writing is held to its key's scope as later lists grant it.
      const socket = yield* resource
        .watch(`Bearer ${key}`, "write")
        .pipe(Effect.flip, Effect.forkChild);

      // Its first check opens the key with real crypto; the clock must not move under it, or
      // its own deadline passes first.
      yield* TestClock.withLive(Effect.sleep("100 millis"));

      // Within a minute the list already read decides, revoked or not.
      granted.set(key, grant(["read"]));
      yield* verify(key);
      assert.equal(lists, 1);

      // The next list reaches every verification, and every watched connection.
      yield* TestClock.adjust("1 minute");
      yield* verify(key);
      // Refused as `admit` would refuse it now: a key cannot step up, so it names no scope.
      const ended = yield* Fiber.join(socket);
      assert(ended instanceof Action.Forbidden);
      assert.deepEqual(sent(ended), sent(new Action.Forbidden({ message: "Requires write." })));
      granted.delete(key);
      yield* TestClock.adjust("1 minute");
      assert((yield* Effect.flip(verify(key))) instanceof Unauthorized);
      assert.equal(lists, 3);

      // An outage is no error while the held list is inside its window, JWKS or not.
      const expiring = `clankerauth_${"e".repeat(64)}`;
      yield* TestClock.adjust("1 minute");
      const held = yield* Clock.currentTimeMillis;
      granted.set(expiring, grant(["read"], held + 30_000));
      yield* verify(reader);
      yield* verify(expiring);
      unavailable = true;
      yield* TestClock.adjust("1 minute");
      yield* verify(reader);
      // A key's own expiry is enforced from the held list, with no issuer to ask.
      assert((yield* Effect.flip(verify(expiring))) instanceof Unauthorized);
      const window = KeyList.lifetime * 1000;
      yield* TestClock.adjust(window - 60_001);
      yield* verify(reader);
      assert.equal(yield* Clock.currentTimeMillis, held + window - 1);

      // Past it, the key is undecided until the issuer answers again.
      yield* TestClock.adjust(1);
      assert((yield* Effect.flip(verify(reader))) instanceof ProviderUnavailable);
      unavailable = false;
      yield* TestClock.adjust("5 seconds");
      yield* verify(reader);

      // An issuer that stops answering fails the read, not the request: it gives up
      // before the request's deadline, and the held list decides, for sockets too.
      const watched = yield* resource.watch(`Bearer ${reader}`).pipe(Effect.flip, Effect.forkChild);

      yield* TestClock.withLive(Effect.sleep("100 millis"));
      stalled = true;
      yield* TestClock.adjust("1 minute");
      const late = yield* verify(reader).pipe(Effect.forkChild);
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      yield* TestClock.adjust("3 seconds");
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      assert.notEqual(late.pollUnsafe(), undefined);
      assert.deepEqual((yield* Fiber.join(late)).actor, { kind: "key", keyId: "key" });
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      assert.equal(watched.pollUnsafe(), undefined);
    }).pipe(Effect.provide(TestClock.layer())),
  );
});

test("a key the held list does not name has the list read again, five seconds apart at most", async () => {
  const { pair, jwk, issuer, audience } = await listIssuer();
  const known = `clankerauth_${"k".repeat(64)}`;
  const created = `clankerauth_${"c".repeat(64)}`;
  const unknown = `clankerauth_${"u".repeat(64)}`;
  const grant = { keyId: "key", ownerId: "owner", scopes: ["read"], expiresAt: null };

  await Effect.runPromise(
    Effect.gen(function* () {
      let lists = 0;
      let unavailable = false;
      const granted = new Map([[known, grant]]);

      const client = HttpClient.make((request) =>
        Effect.gen(function* () {
          if (request.url.endsWith("/jwks"))
            return HttpClientResponse.fromWeb(request, Response.json({ keys: [jwk] }));
          lists++;

          if (unavailable)
            return HttpClientResponse.fromWeb(request, new Response("{}", { status: 503 }));
          const seconds = Math.floor((yield* Clock.currentTimeMillis) / 1000);

          const list = yield* Effect.promise(() =>
            signList(pair.privateKey, issuer, audience, new Map(granted), seconds),
          );

          return HttpClientResponse.fromWeb(request, Response.json({ list }));
        }),
      );

      const resource = yield* resourceOf({
        issuer,
        publicUrl: new URL(audience),
        scopes: ["read"],
        required: "read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const verify = resource.verifier.verifyToken;
      const refused = (key: string) => Effect.flip(verify(key));
      yield* verify(known);

      // A list just read decides a key it does not name, created since or not.
      granted.set(created, grant);
      assert((yield* refused(created)) instanceof Unauthorized);
      assert.equal(lists, 1);

      // Five seconds on it is read again, so a new key waits seconds, not the minute.
      yield* TestClock.adjust("5 seconds");
      yield* verify(created);
      assert.equal(lists, 2);

      // Unknown keys reach the issuer once per five seconds, however many arrive.
      assert((yield* refused(unknown)) instanceof Unauthorized);
      yield* TestClock.adjust("5 seconds");
      assert((yield* refused(unknown)) instanceof Unauthorized);
      assert((yield* refused(unknown)) instanceof Unauthorized);
      assert.equal(lists, 3);

      // A key the list names never does, inside the list's minute.
      yield* TestClock.adjust("59 seconds");
      yield* verify(known);
      yield* verify(created);
      assert.equal(lists, 3);

      // A read that fails refuses the unknown key from the held list, holds off the next
      // read like any other, and leaves that list answering the keys it names.
      unavailable = true;
      assert((yield* refused(unknown)) instanceof Unauthorized);
      assert((yield* refused(unknown)) instanceof Unauthorized);
      assert.equal(lists, 4);
      yield* verify(known);
    }).pipe(Effect.provide(TestClock.layer())),
  );
});

test("a list read shortly before it expires decides only until then", async () => {
  const { pair, jwk, issuer, audience } = await listIssuer();
  const key = `clankerauth_${"k".repeat(64)}`;
  const grant = { keyId: "key", ownerId: "owner", scopes: ["read"], expiresAt: null };

  // Signed long ago, as a delayed or replayed list is: five seconds of its window remain.
  const list = await signList(
    pair.privateKey,
    issuer,
    audience,
    [[key, grant]],
    5 - KeyList.lifetime,
  );

  await Effect.runPromise(
    Effect.gen(function* () {
      const client = HttpClient.make((request) =>
        Effect.succeed(
          HttpClientResponse.fromWeb(
            request,
            request.url.endsWith("/jwks")
              ? Response.json({ keys: [jwk] })
              : Response.json({ list }),
          ),
        ),
      );

      const resource = yield* resourceOf({
        issuer,
        publicUrl: new URL(audience),
        scopes: ["read"],
        required: "read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      yield* resource.verifier.verifyToken(key);
      // Past the window it was signed with, it is read again; the same list, replayed, no
      // longer verifies.
      yield* TestClock.adjust("5 seconds");
      const failure = yield* Effect.flip(resource.verifier.verifyToken(key));
      assert(failure instanceof ProviderUnavailable);
      assert.equal(failure.operation, "key-list.verify");
    }).pipe(Effect.provide(TestClock.layer())),
  );
});

test("a key list that does not verify is an outage, not a refusal", () =>
  Effect.runPromise(
    Effect.gen(function* () {
      const client = HttpClient.make((request) =>
        Effect.succeed(HttpClientResponse.fromWeb(request, Response.json({ list: "not.a.list" }))),
      );

      const resource = yield* resourceOf({
        issuer: "https://issuer.example/api/auth",
        publicUrl: new URL("https://notes.example"),
        scopes: ["notes:read"],
        required: "notes:read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const failure = yield* Effect.flip(resource.verifier.verifyToken("clankerauth_test"));
      assert(failure instanceof ProviderUnavailable);
      assert.equal(failure.operation, "key-list.verify");
    }),
  ));

test("a watched access token holds its connection until it expires, through an outage", async () => {
  const { exportJWK, generateKeyPair, SignJWT } = await import("jose");
  const pair = await generateKeyPair("EdDSA");
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: "issuer", alg: "EdDSA" };
  const issuer = "https://issuer.example/api/auth";
  const audience = "https://notes.example/";

  const token = await new SignJWT({ client_id: "web", scope: "read" })
    .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid: "issuer" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject("owner")
    .setIssuedAt(0)
    .setExpirationTime(900)
    .sign(pair.privateKey);

  await Effect.runPromise(
    Effect.gen(function* () {
      let reads = 0;

      const client = HttpClient.make((request) => {
        reads++;

        return Effect.succeed(
          HttpClientResponse.fromWeb(
            request,
            reads === 1 ? Response.json({ keys: [jwk] }) : new Response("{}", { status: 503 }),
          ),
        );
      });

      const resource = yield* resourceOf({
        issuer,
        publicUrl: new URL(audience),
        scopes: ["read"],
        required: "read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const socket = yield* resource.watch(`Bearer ${token}`).pipe(Effect.flip, Effect.forkChild);

      // Admission runs on real promises; let it finish before time moves.
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      yield* TestClock.adjust("14 minutes");
      assert.equal(reads, 1);
      assert.equal(socket.pollUnsafe(), undefined);
      yield* TestClock.adjust("1 minute");
      // It ends as expired, not as an outage: an expired token is refused without the issuer.
      assert((yield* Fiber.join(socket)) instanceof Action.Unauthenticated);
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

      const resource = yield* resourceOf({
        issuer: "https://issuer.example",
        publicUrl: new URL("https://notes.example"),
        scopes: ["notes:read"],
        required: "notes:read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const failure = yield* Effect.flip(resource.verifier.verifyToken("clankerauth_test"));
      assert(failure instanceof ProviderUnavailable);
      assert.equal(failure.cause, transportCause);

      const error = new Unauthorized({ message: "Sign in required", cause: { secret } });
      assert(!Object.keys(error).includes("cause"));
      assert(!JSON.stringify(error).includes(secret));

      const Private = Action.make("private", {
        description: "Fixture action",
        readOnly: true,
        caller: CurrentPrincipal,
      });

      const PrivateHttp = ActionHttp.make([Private], { authentication: Login });

      // An action route and a host route of its own answer the outage alike.
      const web = HttpRouter.toWebHandler(
        Layer.mergeAll(
          ActionHttp.layer(
            PrivateHttp,
            Action.implement(Private, () => Effect.void, { authorize: Action.allowAll }),
          ),
          HttpRouter.add("GET", "/frame", HttpServerResponse.empty()).pipe(
            Layer.provide(Notes.admitted().layer),
          ),
        ).pipe(
          Layer.provide(Notes.provider),
          Layer.provide(
            Notes.layer({
              issuer: "https://issuer.example",
              publicUrl: new URL("https://notes.example"),
            }),
          ),
          Layer.provide(Layer.succeed(HttpClient.HttpClient, client)),
          Layer.provide(HttpServer.layerServices),
        ),
      );

      yield* Effect.promise(async () => {
        try {
          const response = await web.handler(
            new Request("https://notes.example/api/private", {
              method: "POST",
              headers: {
                authorization: "Bearer clankerauth_test",
                "content-type": "application/json",
              },
              body: "{}",
            }),
          );

          const frame = await web.handler(
            new Request("https://notes.example/frame", {
              headers: { authorization: "Bearer clankerauth_test" },
            }),
          );

          const unavailable = Schema.encodeSync(ProviderUnavailable)(
            new ProviderUnavailable({ operation: "http.request" }),
          );

          for (const answered of [response, frame]) {
            assert.equal(answered.status, 503);
            assert.deepEqual(await answered.json(), unavailable);
          }
        } finally {
          await web.dispose();
        }
      });
    }),
  ));
