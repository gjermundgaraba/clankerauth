import assert from "node:assert/strict";

import { it } from "@effect/vitest";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { Clock, Deferred, Effect, Fiber, Layer, Schema } from "effect";
import {
  HttpClient,
  HttpClientRequest,
  HttpClientResponse,
  HttpRouter,
  HttpServer,
  HttpServerResponse,
} from "effect/http";
import { HttpClientError, TransportError } from "effect/http/HttpClientError";
import { TestClock } from "effect/testing";

import { ProviderUnavailable, Unauthorized } from "../src/errors.ts";
import { Verifier } from "../src/index.ts";
import * as KeyList from "../src/key-list.ts";
import { CurrentPrincipal } from "../src/session.ts";
import {
  json,
  Login,
  Notes,
  resourceOf,
  sent,
  signList,
  webHandler,
} from "./support.ts";

const listIssuer = Effect.promise(async () => {
  const { exportJWK, generateKeyPair } = await import("jose");
  const pair = await generateKeyPair("EdDSA");

  return {
    pair,
    jwk: { ...(await exportJWK(pair.publicKey)), kid: "fixture", alg: "EdDSA" },
    issuer: "https://issuer.example/api/auth",
    audience: "https://notes.example/",
  };
});

const grantOf = (scopes: string[], expiresAt: number | null = null) => ({
  keyId: "key",
  ownerId: "owner",
  scopes,
  expiresAt,
});

it.effect("verification deadlines interrupt the supplied HTTP transport", () =>
  Effect.gen(function* () {
    const started = yield* Deferred.make<undefined>();
    const cancelled = yield* Deferred.make<undefined>();

    const client = HttpClient.make(() =>
      Effect.gen(function* () {
        yield* Deferred.succeed(started, undefined);

        return yield* Effect.never.pipe(
          Effect.ensuring(Deferred.succeed(cancelled, undefined))
        );
      })
    );

    const resource = yield* resourceOf({
      issuer: "https://issuer.example/api/auth",
      publicUrl: new URL("https://notes.example"),
      store: Verifier.store(),
      scopes: ["notes:read"],
      required: "notes:read",
    }).pipe(Effect.provideService(HttpClient.HttpClient, client));

    const header = Buffer.from(
      JSON.stringify({ alg: "EdDSA", kid: "k", typ: "at+jwt" })
    );

    const token = `${header.toString("base64url")}.e30.AA`;

    const fiber = yield* Effect.flip(resource.verifier.verifyToken(token)).pipe(
      Effect.forkChild
    );

    yield* Deferred.await(started);
    yield* TestClock.adjust("5 seconds");
    const error = yield* Fiber.join(fiber);
    assert.ok(error instanceof ProviderUnavailable);
    assert.equal(error.operation, "verify.timeout");
    yield* Deferred.await(cancelled);
  })
);

it.effect(
  "one JWKS read serves every key until it expires, a failed one cools down, and an abandoned one is dropped",
  () =>
    Effect.gen(function* () {
      const { exportJWK, generateKeyPair, SignJWT } = yield* Effect.promise(
        async () => await import("jose")
      );

      const first = yield* Effect.promise(
        async () => await generateKeyPair("EdDSA")
      );

      const second = yield* Effect.promise(
        async () => await generateKeyPair("EdDSA")
      );

      const firstKey = {
        ...(yield* Effect.promise(
          async () => await exportJWK(first.publicKey)
        )),
        kid: "first",
        alg: "EdDSA",
      };

      const secondKey = {
        ...(yield* Effect.promise(
          async () => await exportJWK(second.publicKey)
        )),
        kid: "second",
        alg: "EdDSA",
      };

      const issuer = "https://issuer.example/api/auth";
      const audience = "https://notes.example/";

      const sign = (kid: string, key: CryptoKey) =>
        Effect.promise(
          async () =>
            await new SignJWT({ client_id: "web", scope: "read" })
              .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid })
              .setIssuer(issuer)
              .setAudience(audience)
              .setSubject("owner")
              .setIssuedAt(0)
              .setExpirationTime(2000)
              .sign(key)
        );

      const firstToken = yield* sign("first", first.privateKey);
      const secondToken = yield* sign("second", second.privateKey);
      let reads = 0;
      let unavailable = true;
      let key = firstKey;
      let paused = false;
      const started = yield* Deferred.make<undefined>();

      const client = HttpClient.make((request) =>
        Effect.gen(function* () {
          reads += 1;

          if (paused) {
            yield* Deferred.succeed(started, undefined);

            return yield* Effect.never;
          }

          return HttpClientResponse.fromWeb(
            request,
            Response.json({ keys: [key] }, { status: unavailable ? 503 : 200 })
          );
        })
      );

      const resource = yield* resourceOf({
        issuer,
        publicUrl: new URL(audience),
        store: Verifier.store(),
        scopes: ["read"],
        required: "read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const verify = resource.verifier.verifyToken;

      assert.ok(
        (yield* Effect.flip(verify(firstToken))) instanceof ProviderUnavailable
      );
      assert.ok(
        (yield* Effect.flip(verify(firstToken))) instanceof ProviderUnavailable
      );
      assert.equal(reads, 1);
      unavailable = false;
      yield* TestClock.adjust("5 seconds");

      yield* Effect.all(
        [verify(firstToken), verify(firstToken), verify(firstToken)],
        {
          concurrency: "unbounded",
        }
      );
      assert.equal(reads, 4);

      key = secondKey;
      assert.ok(
        (yield* Effect.flip(verify(secondToken))) instanceof Unauthorized
      );
      assert.equal(reads, 4);

      yield* TestClock.adjust("1 minute");
      yield* verify(secondToken);
      assert.ok(
        (yield* Effect.flip(verify(firstToken))) instanceof Unauthorized
      );
      assert.equal(reads, 5);

      yield* TestClock.adjust("1 minute");
      paused = true;
      const abandoned = yield* verify(secondToken).pipe(Effect.forkChild);
      yield* Deferred.await(started);
      yield* TestClock.adjust("5 seconds");
      const timeout = yield* Effect.flip(Fiber.join(abandoned));
      assert.ok(timeout instanceof ProviderUnavailable);
      assert.equal(timeout.operation, "verify.timeout");
      paused = false;
      yield* verify(secondToken);
      assert.equal(reads, 7);
      yield* TestClock.adjust("5 seconds");
      yield* verify(secondToken);
      assert.equal(reads, 7);
    })
);

it.effect(
  "a key list refreshes every minute, for verifications and watched sockets, and outlasts an outage or a stalled issuer for its lifetime",
  () =>
    Effect.gen(function* () {
      const { pair, jwk, issuer, audience } = yield* listIssuer;
      const key = `clankerauth_${"k".repeat(64)}`;
      const reader = `clankerauth_${"r".repeat(64)}`;

      let lists = 0;
      let unavailable = false;
      let stalled = false;

      const granted = new Map([
        [key, grantOf(["read", "write"])],
        [reader, grantOf(["read"])],
      ]);

      const client = HttpClient.make((request) =>
        Effect.gen(function* () {
          if (stalled) {
            return yield* Effect.never;
          }

          if (unavailable) {
            return HttpClientResponse.fromWeb(
              request,
              new Response("{}", { status: 503 })
            );
          }

          if (request.url.endsWith("/jwks")) {
            return HttpClientResponse.fromWeb(
              request,
              Response.json({ keys: [jwk] })
            );
          }

          lists += 1;
          const seconds = Math.floor((yield* Clock.currentTimeMillis) / 1000);

          const list = yield* Effect.promise(
            async () =>
              await signList(
                pair.privateKey,
                issuer,
                audience,
                new Map(granted),
                seconds
              )
          );

          return HttpClientResponse.fromWeb(request, Response.json({ list }));
        })
      );

      const resource = yield* resourceOf({
        issuer,
        publicUrl: new URL(audience),
        store: Verifier.store(),
        scopes: ["read", "write"],
        required: "read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const verify = resource.verifier.verifyToken;
      yield* TestClock.adjust("1 minute");
      assert.deepEqual((yield* verify(key)).actor, {
        kind: "key",
        keyId: "key",
      });

      const socket = yield* resource
        .watch(`Bearer ${key}`, "write")
        .pipe(Effect.flip, Effect.forkChild);

      yield* TestClock.withLive(Effect.sleep("100 millis"));

      granted.set(key, grantOf(["read"]));
      yield* verify(key);
      assert.equal(lists, 1);

      yield* TestClock.adjust("1 minute");
      yield* verify(key);
      const ended = yield* Fiber.join(socket);
      assert.ok(ended instanceof Action.Forbidden);
      assert.deepEqual(
        sent(ended),
        sent(new Action.Forbidden({ message: "Requires write." }))
      );
      granted.delete(key);
      yield* TestClock.adjust("1 minute");
      assert.ok((yield* Effect.flip(verify(key))) instanceof Unauthorized);
      assert.equal(lists, 4);

      const expiring = `clankerauth_${"e".repeat(64)}`;
      yield* TestClock.adjust("1 minute");
      const held = yield* Clock.currentTimeMillis;
      granted.set(expiring, grantOf(["read"], held + 30_000));
      yield* verify(reader);
      yield* verify(expiring);
      unavailable = true;
      yield* TestClock.adjust("1 minute");
      yield* verify(reader);
      assert.ok((yield* Effect.flip(verify(expiring))) instanceof Unauthorized);
      const window = KeyList.lifetime * 1000;
      yield* TestClock.adjust(window - 60_001);
      yield* verify(reader);
      assert.equal(yield* Clock.currentTimeMillis, held + window - 1);

      yield* TestClock.adjust(1);
      assert.ok(
        (yield* Effect.flip(verify(reader))) instanceof ProviderUnavailable
      );
      unavailable = false;
      yield* TestClock.adjust("5 seconds");
      yield* verify(reader);

      const watched = yield* resource
        .watch(`Bearer ${reader}`)
        .pipe(Effect.flip, Effect.forkChild);

      yield* TestClock.withLive(Effect.sleep("100 millis"));
      stalled = true;
      yield* TestClock.adjust("1 minute");
      const late = yield* verify(reader).pipe(Effect.forkChild);
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      yield* TestClock.adjust("3 seconds");
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      assert.notEqual(late.pollUnsafe(), undefined);
      assert.deepEqual((yield* Fiber.join(late)).actor, {
        kind: "key",
        keyId: "key",
      });
      yield* TestClock.withLive(Effect.sleep("100 millis"));
      assert.equal(watched.pollUnsafe(), undefined);
    })
);

it.effect(
  "a key the held list does not name has the list read again, five seconds apart at most, even when the read fails",
  () =>
    Effect.gen(function* () {
      const { pair, jwk, issuer, audience } = yield* listIssuer;
      const known = `clankerauth_${"k".repeat(64)}`;
      const created = `clankerauth_${"c".repeat(64)}`;
      const unknown = `clankerauth_${"u".repeat(64)}`;

      const grant = {
        keyId: "key",
        ownerId: "owner",
        scopes: ["read"],
        expiresAt: null,
      };

      let lists = 0;
      let unavailable = false;
      const granted = new Map([[known, grant]]);

      const client = HttpClient.make((request) =>
        Effect.gen(function* () {
          if (request.url.endsWith("/jwks")) {
            return HttpClientResponse.fromWeb(
              request,
              Response.json({ keys: [jwk] })
            );
          }

          lists += 1;

          if (unavailable) {
            return HttpClientResponse.fromWeb(
              request,
              new Response("{}", { status: 503 })
            );
          }

          const seconds = Math.floor((yield* Clock.currentTimeMillis) / 1000);

          const list = yield* Effect.promise(
            async () =>
              await signList(
                pair.privateKey,
                issuer,
                audience,
                new Map(granted),
                seconds
              )
          );

          return HttpClientResponse.fromWeb(request, Response.json({ list }));
        })
      );

      const resource = yield* resourceOf({
        issuer,
        publicUrl: new URL(audience),
        store: Verifier.store(),
        scopes: ["read"],
        required: "read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const verify = resource.verifier.verifyToken;
      const refused = (key: string) => Effect.flip(verify(key));
      yield* verify(known);

      granted.set(created, grant);
      assert.ok((yield* refused(created)) instanceof Unauthorized);
      assert.equal(lists, 1);

      yield* TestClock.adjust("5 seconds");
      yield* verify(created);
      assert.equal(lists, 2);

      assert.ok((yield* refused(unknown)) instanceof Unauthorized);
      yield* TestClock.adjust("5 seconds");
      assert.ok((yield* refused(unknown)) instanceof Unauthorized);
      assert.ok((yield* refused(unknown)) instanceof Unauthorized);
      assert.equal(lists, 3);

      yield* TestClock.adjust("59 seconds");
      yield* verify(known);
      yield* verify(created);
      assert.equal(lists, 3);

      unavailable = true;
      assert.ok((yield* refused(unknown)) instanceof Unauthorized);
      assert.ok((yield* refused(unknown)) instanceof Unauthorized);
      assert.equal(lists, 4);
      yield* verify(known);
    })
);

it.effect("a list read shortly before it expires decides only until then", () =>
  Effect.gen(function* () {
    const { pair, jwk, issuer, audience } = yield* listIssuer;
    const key = `clankerauth_${"k".repeat(64)}`;

    const grant = {
      keyId: "key",
      ownerId: "owner",
      scopes: ["read"],
      expiresAt: null,
    };

    const list = yield* Effect.promise(
      async () =>
        await signList(
          pair.privateKey,
          issuer,
          audience,
          [[key, grant]],
          5 - KeyList.lifetime
        )
    );

    const client = HttpClient.make((request) =>
      Effect.succeed(
        HttpClientResponse.fromWeb(
          request,
          request.url.endsWith("/jwks")
            ? Response.json({ keys: [jwk] })
            : Response.json({ list })
        )
      )
    );

    const resource = yield* resourceOf({
      issuer,
      publicUrl: new URL(audience),
      store: Verifier.store(),
      scopes: ["read"],
      required: "read",
    }).pipe(Effect.provideService(HttpClient.HttpClient, client));

    yield* resource.verifier.verifyToken(key);
    yield* TestClock.adjust("5 seconds");
    const failure = yield* Effect.flip(resource.verifier.verifyToken(key));
    assert.ok(failure instanceof ProviderUnavailable);
    assert.equal(failure.operation, "key-list.verify");
  })
);

it.effect("a key list that does not verify is an outage, not a refusal", () =>
  Effect.gen(function* () {
    const client = HttpClient.make((request) =>
      Effect.succeed(
        HttpClientResponse.fromWeb(
          request,
          Response.json({ list: "not.a.list" })
        )
      )
    );

    const resource = yield* resourceOf({
      issuer: "https://issuer.example/api/auth",
      publicUrl: new URL("https://notes.example"),
      store: Verifier.store(),
      scopes: ["notes:read"],
      required: "notes:read",
    }).pipe(Effect.provideService(HttpClient.HttpClient, client));

    const failure = yield* Effect.flip(
      resource.verifier.verifyToken("clankerauth_test")
    );

    assert.ok(failure instanceof ProviderUnavailable);
    assert.equal(failure.operation, "key-list.verify");
  })
);

it.effect(
  "a watched access token holds its connection until it expires, through an outage",
  () =>
    Effect.gen(function* () {
      const { exportJWK, generateKeyPair, SignJWT } = yield* Effect.promise(
        async () => await import("jose")
      );

      const pair = yield* Effect.promise(
        async () => await generateKeyPair("EdDSA")
      );

      const jwk = {
        ...(yield* Effect.promise(async () => await exportJWK(pair.publicKey))),
        kid: "issuer",
        alg: "EdDSA",
      };

      const issuer = "https://issuer.example/api/auth";
      const audience = "https://notes.example/";

      const token = yield* Effect.promise(
        async () =>
          await new SignJWT({ client_id: "web", scope: "read" })
            .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid: "issuer" })
            .setIssuer(issuer)
            .setAudience(audience)
            .setSubject("owner")
            .setIssuedAt(0)
            .setExpirationTime(900)
            .sign(pair.privateKey)
      );

      let reads = 0;

      const client = HttpClient.make((request) => {
        reads += 1;

        return Effect.succeed(
          HttpClientResponse.fromWeb(
            request,
            reads === 1
              ? Response.json({ keys: [jwk] })
              : new Response("{}", { status: 503 })
          )
        );
      });

      const resource = yield* resourceOf({
        issuer,
        publicUrl: new URL(audience),
        store: Verifier.store(),
        scopes: ["read"],
        required: "read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const socket = yield* resource
        .watch(`Bearer ${token}`)
        .pipe(Effect.flip, Effect.forkChild);

      yield* TestClock.withLive(Effect.sleep("100 millis"));
      yield* TestClock.adjust("14 minutes");
      assert.equal(reads, 1);
      assert.equal(socket.pollUnsafe(), undefined);
      yield* TestClock.adjust("1 minute");
      assert.ok((yield* Fiber.join(socket)) instanceof Action.Unauthenticated);
    })
);

it.live(
  "diagnostic causes survive adapters but never enter public error schemas or HTTP bodies",
  () =>
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
        store: Verifier.store(),
        scopes: ["notes:read"],
        required: "notes:read",
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const failure = yield* Effect.flip(
        resource.verifier.verifyToken("clankerauth_test")
      );

      assert.ok(failure instanceof ProviderUnavailable);
      assert.equal(failure.cause, transportCause);

      const error = new Unauthorized({
        message: "Sign in required",
        cause: { secret },
      });

      assert.ok(!Object.keys(error).includes("cause"));
      assert.ok(!JSON.stringify(error).includes(secret));

      const Private = Action.make("private", {
        description: "Fixture action",
        readOnly: true,
        caller: CurrentPrincipal,
      });

      const PrivateHttp = ActionHttp.make([Private], { authentication: Login });

      const web = yield* webHandler(() =>
        HttpRouter.toWebHandler(
          Layer.mergeAll(
            ActionHttp.layer(
              PrivateHttp,
              Action.implement(Private, () => Effect.void, {
                authorize: Action.allowAll,
              })
            ),
            HttpRouter.add("GET", "/frame", HttpServerResponse.empty()).pipe(
              Layer.provide(Notes.admitted().layer)
            )
          ).pipe(
            Layer.provide(Notes.provider),
            Layer.provide(
              Notes.layer({
                issuer: "https://issuer.example",
                publicUrl: new URL("https://notes.example"),
                store: Verifier.store(),
              })
            ),
            Layer.provide(Layer.succeed(HttpClient.HttpClient, client)),
            Layer.provide(HttpServer.layerServices)
          )
        )
      );

      const response = yield* Effect.promise(
        async () =>
          await web.handler(
            new Request("https://notes.example/api/private", {
              method: "POST",
              headers: {
                authorization: "Bearer clankerauth_test",
                "content-type": "application/json",
              },
              body: "{}",
            })
          )
      );

      const frame = yield* Effect.promise(
        async () =>
          await web.handler(
            new Request("https://notes.example/frame", {
              headers: { authorization: "Bearer clankerauth_test" },
            })
          )
      );

      const unavailable = yield* Schema.encodeEffect(ProviderUnavailable)(
        new ProviderUnavailable({ operation: "http.request" })
      );

      for (const answered of [response, frame]) {
        assert.equal(answered.status, 503);
        assert.deepEqual(yield* json(answered), unavailable);
      }
    })
);
