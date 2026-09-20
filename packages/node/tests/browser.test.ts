import { BrowserActions } from "../src/effect-actions.ts";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { test } from "vite-plus/test";
import { Effect, Fiber, Layer, Redacted, Schema } from "effect";
import { BrowserSession, SessionStore, StoreError, Unauthorized } from "../src/index.ts";
import { CurrentPrincipal, Resource } from "../src/effect-actions.ts";
import { HttpRouter, HttpServer, HttpServerResponse } from "effect/unstable/http";
import { TestClock } from "effect/testing";
import { LoginResponse, memoryStore, run, webBrowser, withHttp } from "./support.ts";

const origin = "http://127.0.0.1:7337";

const resource = `${origin}/api`;

const secret = "test-session-secret-32-characters-long";

const request = (path: string, method = "GET", cookie?: string, body?: { returnTo: string }) => {
  const headers = new Headers({ origin });

  if (cookie) headers.set("cookie", cookie);
  const init: RequestInit = { method, headers };

  if (body || method === "POST") {
    headers.set("content-type", "application/json");
    init.body = JSON.stringify(body ?? {});
  }

  return new Request(origin + path, init);
};

const withFixture = async (
  action: (fixture: {
    auth: ReturnType<typeof webBrowser>;
    login: () => Promise<string>;
    beginLogin: () => Promise<{ transaction: string; callbackUrl: string }>;
    tokenRequests: URLSearchParams[];
    rows: Map<string, { payload: string; expires: number }>;
    restart: () => Promise<ReturnType<typeof webBrowser>>;
    failRefresh: (failed?: boolean) => void;
    failWriteAfter: (successfulWrites: number) => void;
    wrongNonce: () => void;
    failDiscovery: (failed: boolean) => void;
    failRevocation: () => void;
    invalidateRefresh: () => void;
    pauseRefresh: () => { started: Promise<void>; release: () => void };
    revoked: string[];
    discoveryReads: () => number;
    issuer: string;
  }) => Promise<void>,
  callbackUrl = `${origin}/auth/callback`,
) => {
  const pair = await generateKeyPair("RS256");
  const jwk = await exportJWK(pair.publicKey);
  let issuer = "";
  let nonce = "";
  let replaceNonce = false;
  let discoveryReads = 0;
  let fail = false;
  let discoveryFailure = false;
  let revocationFailure = false;
  let invalid = false;

  let pause:
    | {
        started: ReturnType<typeof Promise.withResolvers<void>>;
        gate: ReturnType<typeof Promise.withResolvers<void>>;
      }
    | undefined;

  const revoked: string[] = [];
  const tokenRequests: URLSearchParams[] = [];

  const server = createServer(async (req, res) => {
    res.setHeader("content-type", "application/json");

    if (req.url === "/.well-known/openid-configuration") {
      discoveryReads++;

      if (discoveryFailure) {
        res.statusCode = 503;
        res.end("{}");

        return;
      }

      res.end(
        JSON.stringify({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          revocation_endpoint: `${issuer}/revoke`,
        }),
      );
    } else if (req.url === "/jwks") res.end(JSON.stringify({ keys: [jwk] }));
    else if (req.url === "/token") {
      assert.equal(
        req.headers.authorization,
        `Basic ${Buffer.from("web%2Dclient:secret").toString("base64")}`,
      );
      let body = "";

      for await (const chunk of req) body += String(chunk);
      const params = new URLSearchParams(body);
      tokenRequests.push(params);

      if (params.get("grant_type") === "refresh_token" && fail) {
        res.statusCode = 503;
        res.end(JSON.stringify({ error: "temporarily_unavailable" }));

        return;
      }

      const initial = params.get("grant_type") === "authorization_code";

      if (!initial && invalid) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "invalid_grant" }));

        return;
      }

      if (!initial && pause) {
        pause.started.resolve();
        await pause.gate.promise;
      }

      const idToken = await new SignJWT({ nonce: replaceNonce ? "wrong-nonce" : nonce })
        .setProtectedHeader({ alg: "RS256" })
        .setSubject("owner")
        .setIssuer(issuer)
        .setAudience("web-client")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(pair.privateKey);

      res.end(
        JSON.stringify({
          access_token: initial ? "first-access" : "second-access",
          token_type: "Bearer",
          expires_in: initial ? 1 : 3600,
          refresh_token: initial ? "first-refresh" : "second-refresh",
          id_token: initial ? idToken : undefined,
        }),
      );
    } else if (req.url === "/revoke") {
      let body = "";

      for await (const chunk of req) body += String(chunk);
      revoked.push(new URLSearchParams(body).get("token") ?? "");

      if (revocationFailure) res.statusCode = 503;
      res.end("{}");
    } else res.end("{}");
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();

  if (address === null || !(address instanceof Object) || !("port" in address))
    throw new Error("No address");
  issuer = `http://127.0.0.1:${address.port}`;
  const { store, rows } = memoryStore();
  let writesUntilFailure = Infinity;

  const construct = async () =>
    webBrowser(
      await run(
        withHttp(
          BrowserSession.make({
            issuer,
            callbackUrl,
            clientId: "web-client",
            clientSecret: Redacted.make("secret"),
            secret: Redacted.make(secret),
            resource,
            scopes: ["notes:read"],
            cookie: { name: "notes" },
            verifyToken: () =>
              Effect.succeed({
                subject: "owner",
                scopes: ["notes:read"],
                actor: { kind: "client", clientId: "web-client" },
              }),
          }).pipe(
            Effect.provideService(SessionStore, {
              ...store,
              put: (id, payload, expires) =>
                Effect.suspend(() => {
                  if (writesUntilFailure-- === 0)
                    return Effect.fail(new StoreError({ operation: "put" }));

                  return store.put(id, payload, expires);
                }),
            }),
          ),
        ),
      ),
    );

  const auth = await construct();

  const beginLogin = async () => {
    const result = await auth.login(
      request("/auth/browser/login", "POST", undefined, { returnTo: "/#board" }),
    );

    assert.equal(result.status, 200, await result.clone().text());
    assert.equal(result.headers.get("cache-control"), "no-store");
    assert.equal(result.headers.get("referrer-policy"), "no-referrer");
    const body = Schema.decodeUnknownSync(LoginResponse)(await result.json());
    const authorization = new URL(body.url);
    assert.equal(authorization.searchParams.get("resource"), resource);
    assert.equal(authorization.searchParams.get("redirect_uri"), callbackUrl);
    assert.equal(authorization.searchParams.get("scope"), "openid offline_access notes:read");
    assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
    nonce = authorization.searchParams.get("nonce") ?? "";
    const transaction = result.headers.get("set-cookie")?.split(";")[0];
    assert(transaction);
    assert(transaction.startsWith("notes_login="));

    const callback = new URL(callbackUrl);
    callback.searchParams.set("code", "test");
    callback.searchParams.set("iss", issuer);
    callback.searchParams.set("state", authorization.searchParams.get("state") ?? "");

    return { transaction, callbackUrl: callback.pathname + callback.search };
  };

  const login = async () => {
    const { transaction, callbackUrl } = await beginLogin();
    const callback = await auth.callback(request(callbackUrl, "GET", transaction));
    assert.equal(callback.status, 302, await callback.text());
    assert.equal(callback.headers.get("referrer-policy"), "no-referrer");
    assert.equal(callback.headers.get("location"), `${origin}/#board`);
    assert.match(callback.headers.getSetCookie()[0] ?? "", /Max-Age=2592000(?:;|$)/u);
    const cookie = callback.headers.getSetCookie()[0]?.split(";")[0] ?? "";
    assert(cookie.startsWith("notes_session="));

    return cookie;
  };

  try {
    await action({
      auth,
      login,
      beginLogin,
      tokenRequests,
      rows,
      restart: construct,
      invalidateRefresh: () => {
        invalid = true;
      },
      pauseRefresh: () => {
        pause = { started: Promise.withResolvers<void>(), gate: Promise.withResolvers<void>() };

        return { started: pause.started.promise, release: pause.gate.resolve };
      },
      revoked,
      discoveryReads: () => discoveryReads,
      issuer,
      wrongNonce: () => {
        replaceNonce = true;
      },
      failWriteAfter: (count) => {
        writesUntilFailure = count;
      },
      failRefresh: (failed = true) => {
        fail = failed;
      },
      failDiscovery: (failed) => {
        discoveryFailure = failed;
      },
      failRevocation: () => {
        revocationFailure = true;
      },
    });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
};

const unauthorized = async (action: Promise<unknown>) => {
  await assert.rejects(action, (error) => error instanceof Unauthorized);
};

test("login seals storage, refreshes once concurrently, survives restart, and logs out", () =>
  withFixture(async ({ auth, login, tokenRequests, rows, restart, issuer }) => {
    const cookie = await login();
    const persisted = JSON.stringify([...rows]);
    assert(!persisted.includes("first-access"));
    assert(!persisted.includes("first-refresh"));
    assert(!persisted.includes(cookie.split("=")[1] ?? "missing"));

    const requests = Array.from({ length: 4 }, () =>
      auth.accessToken(request("/api", "GET", cookie)),
    );

    assert.deepEqual(
      await Promise.all(requests),
      Array.from({ length: 4 }, () => "second-access"),
    );
    assert.equal(tokenRequests.length, 2);
    assert(tokenRequests.every((params) => params.get("resource") === resource));
    assert.equal(
      await (await restart()).accessToken(request("/api", "GET", cookie)),
      "second-access",
    );
    const session = await auth.session(request("/auth/browser/session", "POST", cookie));
    assert.equal(session.status, 200);
    assert.deepEqual(await session.json(), {
      subject: "owner",
      scopes: ["notes:read"],
      issuer,
    });
    const logout = await auth.logout(request("/auth/browser/logout", "POST", cookie));
    assert.equal(logout.status, 200);
    assert.match(logout.headers.get("set-cookie") ?? "", /^notes_session=; .*Max-Age=0/u);
    await unauthorized(auth.accessToken(request("/api", "GET", cookie)));
  }));

test("ambiguous refresh failure invalidates the session even after recovery and restart", () =>
  withFixture(async ({ auth, login, tokenRequests, failRefresh, restart, rows }) => {
    const cookie = await login();
    failRefresh();
    assert.equal(
      (await auth.session(request("/auth/browser/session", "POST", cookie))).status,
      503,
    );
    failRefresh(false);
    assert.equal(
      (await auth.session(request("/auth/browser/session", "POST", cookie))).status,
      401,
    );
    assert.equal(
      (await (await restart()).session(request("/auth/browser/session", "POST", cookie))).status,
      401,
    );
    assert.equal(tokenRequests.length, 2);
    assert.equal(rows.size, 0);
  }));

test("restart invalidates a persisted refresh marker without replay", () =>
  withFixture(async ({ login, tokenRequests, restart, rows }) => {
    const cookie = await login();
    // Model a process stopping after the durable marker, before the refresh outcome is recorded.
    const iv = randomBytes(12);
    const key = createHash("sha256").update(secret).digest();
    const cipher = createCipheriv("aes-256-gcm", key, iv);

    const encrypted = Buffer.concat([
      cipher.update(
        JSON.stringify({
          accessToken: "first-access",
          refreshToken: "first-refresh",
          accessExpires: 0,
          subject: "owner",
          refreshBlocked: true,
        }),
      ),
      cipher.final(),
    ]);

    const payload = Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url");

    for (const [id, row] of rows) rows.set(id, { ...row, payload });
    assert.equal(
      (await (await restart()).session(request("/auth/browser/session", "POST", cookie))).status,
      401,
    );
    assert.equal(tokenRequests.length, 1);
    assert.equal(rows.size, 0);
  }));

test("discovery failure before refresh remains retryable", () =>
  withFixture(async ({ login, tokenRequests, restart, failDiscovery, rows }) => {
    const cookie = await login();
    const auth = await restart();
    failDiscovery(true);
    assert.equal(
      (await auth.session(request("/auth/browser/session", "POST", cookie))).status,
      503,
    );
    assert.equal(tokenRequests.length, 1);
    assert.equal(rows.size, 1);
    failDiscovery(false);
    assert.equal(
      (await auth.session(request("/auth/browser/session", "POST", cookie))).status,
      200,
    );
    assert.equal(tokenRequests.length, 2);
  }));

test("cross-origin mutations, unbound callbacks and bad return destinations are rejected", () =>
  withFixture(async ({ auth }) => {
    const rejected = await auth.login(
      new Request(`${origin}/auth/browser/login`, {
        method: "POST",
        headers: { origin: "https://evil.example", "content-type": "application/json" },
        body: JSON.stringify({ returnTo: "/" }),
      }),
    );

    assert.equal(rejected.status, 403);
    assert.equal(rejected.headers.get("cache-control"), "no-store");
    assert.equal(rejected.headers.get("referrer-policy"), "no-referrer");
    assert.equal(
      (await auth.callback(request("/auth/callback?code=stolen&state=unknown"))).headers.get(
        "location",
      ),
      `${origin}/?auth_error=login_failed`,
    );

    for (const returnTo of ["//evil.example", "/auth/callback", "https://evil.example/", "board"])
      assert.equal(
        (await auth.login(request("/auth/browser/login", "POST", undefined, { returnTo }))).status,
        400,
        returnTo,
      );
    assert.equal((await auth.session(request("/auth/browser/session", "POST"))).status, 401);

    for (const body of ["{}", "invalid", JSON.stringify({ returnTo: "http://[invalid" })]) {
      const invalid = new Request(`${origin}/auth/browser/login`, {
        method: "POST",
        headers: { origin, "content-type": "application/json" },
        body,
      });

      assert.equal((await auth.login(invalid)).status, 400);
    }
  }));

test("incorrect callback state consumes the transaction without exchanging a code", () =>
  withFixture(async ({ auth, beginLogin, rows, tokenRequests }) => {
    const { transaction, callbackUrl } = await beginLogin();
    const wrongState = new URL(callbackUrl, origin);
    wrongState.searchParams.set("state", "wrong");
    assert.equal(rows.size, 1);

    const rejected = await auth.callback(
      request(wrongState.pathname + wrongState.search, "GET", transaction),
    );

    assert.equal(rejected.headers.get("location"), `${origin}/?auth_error=login_failed`);
    assert.equal(rows.size, 0);
    assert.equal(tokenRequests.length, 0);
    const retry = await auth.callback(request(callbackUrl, "GET", transaction));
    assert.equal(retry.headers.get("location"), `${origin}/?auth_error=login_failed`);
    assert.equal(tokenRequests.length, 0);
  }));

test("a successful callback consumes its transaction and cannot be replayed", () =>
  withFixture(async ({ auth, beginLogin, rows, tokenRequests }) => {
    const { transaction, callbackUrl } = await beginLogin();
    const callback = () => auth.callback(request(callbackUrl, "GET", transaction));
    assert.equal((await callback()).headers.get("location"), `${origin}/#board`);
    assert.equal(rows.size, 1);
    assert.equal([...rows.keys()].filter((id) => id.startsWith("login:")).length, 0);
    assert.equal(tokenRequests.length, 1);
    const persisted = JSON.stringify([...rows]);
    assert.equal((await callback()).headers.get("location"), `${origin}/?auth_error=login_failed`);
    assert.equal(tokenRequests.length, 1);
    assert.equal(JSON.stringify([...rows]), persisted);
  }));

test("logout waits for an admitted refresh and revokes the rotated credential", () =>
  withFixture(async ({ auth, login, pauseRefresh, revoked }) => {
    const cookie = await login();
    const gate = pauseRefresh();
    const refresh = auth.accessToken(request("/api", "GET", cookie));
    await gate.started;
    const logout = auth.logout(request("/auth/browser/logout", "POST", cookie));
    gate.release();
    assert.equal(await refresh, "second-access");
    assert.equal((await logout).status, 200);
    assert.deepEqual(revoked, ["second-refresh"]);
    await unauthorized(auth.accessToken(request("/api", "GET", cookie)));
  }));

test("logout stays local when the issuer fails to revoke, and reports it", () =>
  withFixture(async ({ auth, login, failRevocation, revoked, rows }) => {
    const cookie = await login();
    failRevocation();
    const logout = await auth.logout(request("/auth/browser/logout", "POST", cookie));
    assert.equal(logout.status, 200);
    assert.deepEqual(revoked, ["first-refresh"]);
    assert.equal(rows.size, 0);
    await unauthorized(auth.accessToken(request("/api", "GET", cookie)));
  }));

test("invalid refresh grants remove the local session without reporting a failure", () =>
  withFixture(async ({ auth, login, invalidateRefresh, rows }) => {
    const cookie = await login();
    invalidateRefresh();
    await unauthorized(auth.accessToken(request("/api", "GET", cookie)));
    assert.equal(rows.size, 0);
  }));

test("interruption after refresh admission preserves the durable marker and forbids replay", () =>
  withFixture(async ({ auth, login, pauseRefresh, restart, tokenRequests, rows }) => {
    const cookie = await login();
    const gate = pauseRefresh();
    const fiber = Effect.runFork(auth.native.accessToken(cookie.slice(cookie.indexOf("=") + 1)));
    await gate.started;

    try {
      await run(Fiber.interrupt(fiber));
      assert.equal(rows.size, 1);
      assert.equal(
        (await (await restart()).session(request("/auth/browser/session", "POST", cookie))).status,
        401,
      );
      assert.equal(tokenRequests.length, 2);
      assert.equal(rows.size, 0);
    } finally {
      gate.release();
    }
  }));

test("corrupt persisted credentials reject authentication without making a refresh request", () =>
  withFixture(async ({ auth, login, rows, tokenRequests }) => {
    const cookie = await login();

    for (const [id, row] of rows) rows.set(id, { ...row, payload: "corrupt" });
    await unauthorized(auth.accessToken(request("/api", "GET", cookie)));
    assert.equal(tokenRequests.length, 1);
  }));

test("session expiration uses Effect time and deletes the expired row", () =>
  withFixture(async ({ auth, login, rows, tokenRequests }) => {
    const cookie = await login();
    const expires = Math.max(...[...rows.values()].map((row) => row.expires));

    const error = await run(
      Effect.gen(function* () {
        yield* TestClock.setTime(expires + 1);

        return yield* Effect.flip(auth.native.accessToken(cookie.slice(cookie.indexOf("=") + 1)));
      }).pipe(Effect.provide(TestClock.layer())),
    );

    assert(error instanceof Unauthorized);
    assert.equal(rows.size, 0);
    assert.equal(tokenRequests.length, 1);
  }));

test("a failed durable marker prevents the refresh request; a failed replacement cannot replay it", () =>
  withFixture(async ({ auth, login, failWriteAfter, tokenRequests, rows }) => {
    const cookie = await login();
    failWriteAfter(0);
    assert.equal(
      (await auth.session(request("/auth/browser/session", "POST", cookie))).status,
      503,
    );
    assert.equal(tokenRequests.length, 1);
    assert.equal(rows.size, 1);
    failWriteAfter(1);
    assert.equal(
      (await auth.session(request("/auth/browser/session", "POST", cookie))).status,
      503,
    );
    assert.equal(tokenRequests.length, 2);
    assert.equal(rows.size, 0);
    assert.equal(
      (await auth.session(request("/auth/browser/session", "POST", cookie))).status,
      401,
    );
    assert.equal(tokenRequests.length, 2);
  }));

test("cookie authentication checks mutation origins, yields to bearer, and supplies CurrentPrincipal", () =>
  withFixture(async ({ auth, login, issuer }) => {
    const cookie = await login();

    const configured = await run(
      withHttp(Resource.make({ issuer, resource, scopes: ["notes:read"] })),
    );

    // The protocol fixture returns opaque access tokens; cryptographic verification is covered
    // by verify.test and the real-issuer lifecycle test. This adapter checks transport policy.
    const fixtureResource: Resource.Resource = {
      ...configured,
      verifier: {
        verify: () => Effect.fail(new Unauthorized({ message: "Bearer required" })),
        verifyToken: (token) =>
          token === "second-access"
            ? Effect.succeed({
                subject: "owner",
                scopes: ["notes:read"],
                actor: { kind: "client", clientId: "web-client" },
              })
            : Effect.fail(new Unauthorized({ message: "Invalid fixture token" })),
      },
    };

    const identity = Effect.map(CurrentPrincipal, (principal) =>
      HttpServerResponse.jsonUnsafe({ subject: principal.subject }),
    );

    const web = HttpRouter.toWebHandler(
      Layer.mergeAll(
        BrowserActions.layer(auth.native),
        HttpRouter.add("GET", "/identity", identity).pipe(
          Layer.provide(Resource.middleware(fixtureResource, { browser: auth.native }).layer),
        ),
        HttpRouter.add("POST", "/write", identity).pipe(
          Layer.provide(Resource.middleware(fixtureResource, { browser: auth.native }).layer),
        ),
        HttpRouter.add("GET", "/bearer", identity).pipe(
          Layer.provide(Resource.middleware(configured).layer),
        ),
      ).pipe(Layer.provide(HttpServer.layerServices)),
    );

    try {
      const crossOrigin = await web.handler(
        new Request(origin + "/write", {
          method: "POST",
          headers: { cookie, origin: "https://evil.example" },
        }),
      );

      assert.equal(crossOrigin.status, 403);
      assert.equal(
        (
          await web.handler(
            new Request(origin + "/write", {
              method: "POST",
              headers: { cookie },
            }),
          )
        ).status,
        403,
      );
      assert.equal(
        (
          await web.handler(
            new Request(origin + "/write", {
              method: "POST",
              headers: { origin, authorization: "Bearer second-access" },
            }),
          )
        ).status,
        401,
      );

      const accepted = await web.handler(
        new Request(origin + "/write", {
          method: "POST",
          headers: { cookie, origin },
        }),
      );

      assert.equal(accepted.status, 200);
      assert.deepEqual(await accepted.json(), { subject: "owner" });
      assert.equal((await web.handler(request("/identity", "GET", cookie))).status, 200);
      assert.equal((await web.handler(request("/bearer", "GET", cookie))).status, 401);
      assert.equal(
        (await web.handler(request("/auth/browser/session", "POST", cookie))).status,
        200,
      );
    } finally {
      await web.dispose();
    }
  }));

test("an ID-token nonce mismatch is a rejected login and cannot replay the consumed transaction", () =>
  withFixture(async ({ auth, beginLogin, wrongNonce, rows, tokenRequests }) => {
    const { transaction, callbackUrl } = await beginLogin();
    wrongNonce();
    const response = await auth.callback(request(callbackUrl, "GET", transaction));
    assert.equal(response.headers.get("location"), origin + "/?auth_error=login_failed");
    assert.equal(rows.size, 0);
    assert.equal(tokenRequests.length, 1);
    await auth.callback(request(callbackUrl, "GET", transaction));
    assert.equal(tokenRequests.length, 1);
  }));

for (const callbackUrl of [
  `${origin}/auth/callback`,
  `${origin}/workspace/oauth/complete?client=notes`,
]) {
  test(`the callback is mounted at the configured pathname: ${callbackUrl}`, () =>
    withFixture(async ({ auth, beginLogin, tokenRequests }) => {
      const web = HttpRouter.toWebHandler(
        BrowserActions.layer(auth.native).pipe(Layer.provide(HttpServer.layerServices)),
      );

      try {
        const started = await beginLogin();

        const response = await web.handler(
          request(started.callbackUrl, "GET", started.transaction),
        );

        assert.equal(response.status, 302);
        assert.equal(response.headers.get("location"), `${origin}/#board`);
        assert.match(response.headers.getSetCookie()[0] ?? "", /^notes_session=/);
        assert.equal(tokenRequests.at(-1)?.get("redirect_uri"), callbackUrl);
      } finally {
        await web.dispose();
      }

      for (const suffix of ["", "?x=1", "#fragment"]) {
        const rejected = await auth.login(
          request("/auth/browser/login", "POST", undefined, {
            returnTo: auth.native.callbackPath + suffix,
          }),
        );

        assert.equal(rejected.status, 400);
      }

      assert.equal(
        (
          await auth.login(
            request("/auth/browser/login", "POST", undefined, {
              returnTo: "/auth/account",
            }),
          )
        ).status,
        200,
      );
    }, callbackUrl));
}

test("a root-mounted callback reports failure without redirecting back to itself", () =>
  withFixture(async ({ auth }) => {
    const response = await auth.callback(request("/"));
    assert.equal(response.status, 401);
    assert.equal(response.headers.get("location"), null);
    assert.match(response.headers.get("set-cookie") ?? "", /^notes_login=; .*Max-Age=0/u);
    assert.deepEqual(
      await response.json(),
      Schema.encodeSync(Unauthorized)(new Unauthorized({ message: "Sign in required" })),
    );
  }, `${origin}/`));
