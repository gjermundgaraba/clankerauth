import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "vite-plus/test";
import { Cause, Deferred, Effect, Exit, Fiber, Layer, Redacted, Schema } from "effect";
import { HttpClientError, TransportError } from "effect/unstable/http/HttpClientError";
import { authenticationErrors } from "../src/errors.ts";
import { TestClock } from "effect/testing";
import {
  HttpClient,
  HttpClientRequest,
  HttpClientResponse,
  HttpRouter,
  HttpServer,
  HttpServerResponse,
} from "effect/unstable/http";
import {
  BrowserSession,
  ConfigurationError,
  Forbidden,
  ProviderUnavailable,
  SessionStore,
  StoreError,
  Unauthorized,
} from "../src/index.ts";
import { Resource } from "../src/effect-actions.ts";
import { memoryStore, run, webBrowser } from "./support.ts";

test("verification deadlines interrupt the supplied HTTP transport", () =>
  run(
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
        resource: "https://notes.example/api",
        scopes: [],
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

test("store failures stay typed and defects are not converted to authentication outcomes", () =>
  run(
    Effect.gen(function* () {
      const { store } = memoryStore();

      const client = HttpClient.make((request) =>
        Effect.succeed(
          HttpClientResponse.fromWeb(
            request,
            Response.json({
              issuer: "https://issuer.example",
              authorization_endpoint: "https://issuer.example/authorize",
            }),
          ),
        ),
      );

      const make = BrowserSession.make({
        issuer: "https://issuer.example",
        callbackUrl: "https://notes.example/auth/callback",
        resource: "https://notes.example/api",
        clientId: "web",
        clientSecret: Redacted.make("secret"),
        secret: Redacted.make(randomBytes(32).toString("hex")),
        scopes: [],
        cookie: { name: "notes" },
        verifyToken: () => Effect.die("unused"),
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const browser = yield* make.pipe(
        Effect.provideService(SessionStore, {
          ...store,
          get: () => Effect.fail(new StoreError({ operation: "get" })),
        }),
      );

      assert((yield* Effect.flip(browser.accessToken("opaque"))) instanceof StoreError);

      const broken = yield* make.pipe(
        Effect.provideService(SessionStore, {
          ...store,
          get: () => Effect.die("broken store invariant"),
        }),
      );

      const exit = yield* Effect.exit(broken.accessToken("opaque"));
      assert(Exit.isFailure(exit));
      assert(exit.cause.reasons.some(Cause.isDieReason));
    }),
  ));

test("JWKS lookups refresh unknown keys once per cooldown, expire normally, and retry initial outages", async () => {
  const { exportJWK, generateKeyPair, SignJWT } = await import("jose");
  const first = await generateKeyPair("EdDSA");
  const second = await generateKeyPair("EdDSA");
  const firstKey = { ...(await exportJWK(first.publicKey)), kid: "first", alg: "EdDSA" };
  const secondKey = { ...(await exportJWK(second.publicKey)), kid: "second", alg: "EdDSA" };
  const issuer = "https://issuer.example/api/auth";
  const audience = "https://notes.example/api";

  const sign = (kid: string, key: CryptoKey) =>
    new SignJWT({ client_id: "web", grant_generation: "g1", scope: "read" })
      .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject("owner")
      .setIssuedAt(0)
      .setExpirationTime(2000)
      .sign(key);

  const firstToken = await sign("first", first.privateKey);
  const secondToken = await sign("second", second.privateKey);
  await run(
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

      const resource = yield* Resource.make({ issuer, resource: audience, scopes: ["read"] }).pipe(
        Effect.provideService(HttpClient.HttpClient, client),
      );

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

test("OAuth's Promise transport bridge preserves defects from the supplied Effect client", () =>
  run(
    Effect.gen(function* () {
      const { store } = memoryStore();

      const browser = yield* BrowserSession.make({
        issuer: "https://issuer.example",
        callbackUrl: "https://notes.example/auth/callback",
        resource: "https://notes.example/api",
        clientId: "web",
        clientSecret: Redacted.make("secret"),
        secret: Redacted.make(randomBytes(32).toString("hex")),
        scopes: [],
        cookie: { name: "notes" },
        verifyToken: () => Effect.die("unused"),
      }).pipe(
        Effect.provideService(SessionStore, store),
        Effect.provideService(
          HttpClient.HttpClient,
          HttpClient.make(() => Effect.die("broken transport invariant")),
        ),
      );

      const exit = yield* Effect.exit(browser.login("/"));
      assert(Exit.isFailure(exit));
      assert(exit.cause.reasons.some(Cause.isDieReason));
    }),
  ));

test("cookie configuration uses Effect's cookie grammar", () =>
  run(
    Effect.gen(function* () {
      const make = (name: string) =>
        BrowserSession.make({
          issuer: "https://issuer.example",
          callbackUrl: "https://notes.example/auth/callback",
          resource: "https://notes.example/api",
          clientId: "web",
          clientSecret: Redacted.make("secret"),
          secret: Redacted.make("a".repeat(32)),
          scopes: [],
          cookie: { name },
          verifyToken: () => Effect.die("unused"),
        }).pipe(
          Effect.provideService(SessionStore, memoryStore().store),
          Effect.provideService(
            HttpClient.HttpClient,
            HttpClient.make((request) =>
              Effect.succeed(
                HttpClientResponse.fromWeb(
                  request,
                  Response.json({
                    issuer: "https://issuer.example",
                    authorization_endpoint: "https://issuer.example/authorize",
                  }),
                ),
              ),
            ),
          ),
        );

      const browser = yield* make("notes.v1");

      const response = yield* Effect.promise(() =>
        webBrowser(browser).login(
          new Request("https://notes.example/auth/browser/login", {
            method: "POST",
            headers: { origin: "https://notes.example", "content-type": "application/json" },
            body: JSON.stringify({ returnTo: "/" }),
          }),
        ),
      );

      assert.equal(response.status, 200);
      assert.match(response.headers.get("set-cookie") ?? "", /^notes\.v1_login=/);

      for (const name of ["notes v1", "notes;v1", "notes=v1"]) {
        const error = yield* Effect.flip(make(name));
        assert.equal(error._tag, "ConfigurationError");
      }
    }),
  ));

test("diagnostic causes survive adapters but never enter public error schemas or HTTP bodies", () =>
  run(
    Effect.gen(function* () {
      const secret = "private-provider-diagnostic";
      const request = HttpClientRequest.get("https://issuer.example/jwks");

      const transportCause = new HttpClientError({
        reason: new TransportError({ request, cause: new Error(secret) }),
      });

      const client = HttpClient.make(() => Effect.fail(transportCause));

      const resource = yield* Resource.make({
        issuer: "https://issuer.example",
        resource: "https://notes.example/api",
        scopes: [],
      }).pipe(Effect.provideService(HttpClient.HttpClient, client));

      const failure = yield* Effect.flip(resource.verifier.verifyToken("ca_test"));
      assert(failure instanceof ProviderUnavailable);
      assert.equal(failure.cause, transportCause);

      const make = BrowserSession.make({
        issuer: "https://issuer.example",
        callbackUrl: "https://notes.example/auth/callback",
        resource: "https://notes.example/api",
        clientId: "web",
        clientSecret: Redacted.make("secret"),
        secret: Redacted.make("a".repeat(32)),
        scopes: [],
        cookie: { name: "notes" },
        verifyToken: resource.verifier.verifyToken,
      }).pipe(Effect.provideService(SessionStore, memoryStore().store));

      const browser = yield* make.pipe(Effect.provideService(HttpClient.HttpClient, client));
      const oauthFailure = yield* Effect.flip(browser.login("/"));
      assert(oauthFailure instanceof ProviderUnavailable);
      assert.equal(oauthFailure.cause, transportCause);

      const malformed = yield* make.pipe(
        Effect.provideService(
          HttpClient.HttpClient,
          HttpClient.make((request) =>
            Effect.succeed(HttpClientResponse.fromWeb(request, Response.json({ issuer: secret }))),
          ),
        ),
      );

      const processingFailure = yield* Effect.flip(malformed.login("/"));
      assert(processingFailure instanceof ProviderUnavailable);
      assert(processingFailure.cause instanceof Error);
      assert("code" in processingFailure.cause);

      for (const error of [
        new Unauthorized({ message: "Sign in required", cause: { secret } }),
        new StoreError({ operation: "get", cause: { secret } }),
        processingFailure,
      ]) {
        const encoded = Schema.encodeSync(Schema.Union(authenticationErrors))(error);
        assert(!("cause" in encoded));
        assert(!JSON.stringify(encoded).includes(secret));
        assert(!JSON.stringify(error).includes(secret));
      }

      const response = yield* Effect.promise(() =>
        webBrowser(browser).login(
          new Request("https://notes.example/auth/browser/login", {
            method: "POST",
            headers: { origin: "https://notes.example", "content-type": "application/json" },
            body: JSON.stringify({ returnTo: "/" }),
          }),
        ),
      );

      assert.equal(response.status, 503);
      assert.deepEqual(
        yield* Effect.promise(() => response.json()),
        Schema.encodeSync(ProviderUnavailable)(
          new ProviderUnavailable({ operation: "http.request" }),
        ),
      );

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

test("invalid discovery endpoints produce sanitized 503 responses and are not cached", () =>
  run(
    Effect.gen(function* () {
      const origin = "https://notes.example";
      let endpoint: string | undefined;

      const browser = yield* BrowserSession.make({
        issuer: "https://issuer.example",
        callbackUrl: `${origin}/auth/callback`,
        resource: `${origin}/api`,
        clientId: "web",
        clientSecret: Redacted.make("secret"),
        secret: Redacted.make("a".repeat(32)),
        scopes: [],
        cookie: { name: "notes" },
        verifyToken: () => Effect.die("unused"),
      }).pipe(
        Effect.provideService(SessionStore, memoryStore().store),
        Effect.provideService(
          HttpClient.HttpClient,
          HttpClient.make((request) =>
            Effect.sync(() =>
              HttpClientResponse.fromWeb(
                request,
                Response.json({
                  issuer: "https://issuer.example",
                  authorization_endpoint: endpoint,
                }),
              ),
            ),
          ),
        ),
      );

      const web = webBrowser(browser);

      for (endpoint of [
        undefined,
        "not a URL",
        "ftp://issuer.example/authorize",
        "http://issuer.example/authorize",
      ]) {
        const response = yield* Effect.promise(() =>
          web.login(
            new Request(`${origin}/auth/browser/login`, {
              method: "POST",
              headers: { origin, "content-type": "application/json" },
              body: JSON.stringify({ returnTo: "/" }),
            }),
          ),
        );

        assert.equal(response.status, 503);
        assert.deepEqual(
          yield* Effect.promise(() => response.json()),
          Schema.encodeSync(ProviderUnavailable)(
            new ProviderUnavailable({ operation: "browser.discovery" }),
          ),
        );
      }

      endpoint = "https://issuer.example/authorize";
      const result = yield* browser.login("/");
      assert.equal(new URL(result.url).origin, "https://issuer.example");
    }),
  ));

test("browser callback configuration validates URLs and derives origin and cookie security", () =>
  run(
    Effect.gen(function* () {
      const make = (callbackUrl: string) =>
        BrowserSession.make({
          issuer: "https://issuer.example",
          callbackUrl,
          resource: "https://notes.example/api",
          clientId: "web",
          clientSecret: Redacted.make("secret"),
          secret: Redacted.make("a".repeat(32)),
          scopes: [],
          cookie: { name: "notes" },
          verifyToken: () => Effect.die("unused"),
        }).pipe(
          Effect.provideService(SessionStore, memoryStore().store),
          Effect.provideService(
            HttpClient.HttpClient,
            HttpClient.make(() => Effect.die("construction must not perform I/O")),
          ),
        );

      for (const callbackUrl of [
        "not a URL",
        "/auth/callback",
        "file:///tmp/app",
        "data:text/plain,app",
        "ftp://notes.example/callback",
        "https://user:password@notes.example/callback",
        "https://notes.example/callback#fragment",
        "https://notes.example/callback#",
      ]) {
        const error = yield* Effect.flip(make(callbackUrl));
        assert(error instanceof ConfigurationError, callbackUrl);
      }

      for (const callbackUrl of [
        "https://notes.example/workspace/callback?client=web",
        "http://127.0.0.1:7337/workspace/callback",
      ]) {
        const browser = yield* make(callbackUrl);
        const parsed = new URL(callbackUrl);
        assert.equal(browser.origin, parsed.origin);
        assert.equal(browser.callbackPath, parsed.pathname);
        assert.equal(browser.cookie.secure, parsed.protocol === "https:");
        yield* browser.checkOrigin(parsed.origin);
        assert(
          (yield* Effect.flip(browser.checkOrigin("https://another.example"))) instanceof Forbidden,
        );
      }
    }),
  ));
