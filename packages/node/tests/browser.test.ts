import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { test } from "vite-plus/test";
import {
  AuthError,
  createBrowserSession,
  type BrowserSession,
  type BrowserSessionStore,
} from "../src/index.ts";

const origin = "http://127.0.0.1:7337";
const resource = `${origin}/api`;
const secret = "test-session-secret-32-characters-long";
const request = (path: string, method = "GET", cookie?: string, body?: { returnTo: string }) => {
  const headers = new Headers({ origin });
  if (cookie) headers.set("cookie", cookie);
  const init: RequestInit = { method, headers };
  if (body) {
    headers.set("content-type", "application/json");
    init.body = JSON.stringify(body);
  }
  return new Request(origin + path, init);
};

/** The store contract, implemented in memory. Consumers back it with their database. */
const memoryStore = () => {
  const rows = new Map<string, { payload: string; expires: number }>();
  const store: BrowserSessionStore = {
    get: async (id) => rows.get(id),
    put: async (id, payload, expires) => {
      rows.set(id, { payload, expires });
    },
    delete: async (id) => {
      rows.delete(id);
    },
    sweep: async (now) => {
      for (const [id, row] of rows) if (row.expires <= now) rows.delete(id);
    },
  };
  return { store, rows };
};

const withFixture = async (
  action: (fixture: {
    auth: BrowserSession;
    login: () => Promise<string>;
    beginLogin: () => Promise<{ transaction: string; callbackUrl: string }>;
    tokenRequests: URLSearchParams[];
    rows: Map<string, { payload: string; expires: number }>;
    restart: () => BrowserSession;
    failRefresh: (failed?: boolean) => void;
    failDiscovery: (failed: boolean) => void;
    invalidateRefresh: () => void;
    pauseRefresh: () => { started: Promise<void>; release: () => void };
    revoked: string[];
    discoveryReads: () => number;
    failures: string[];
    issuer: string;
  }) => Promise<void>,
) => {
  const pair = await generateKeyPair("RS256");
  const jwk = await exportJWK(pair.publicKey);
  let issuer = "";
  let nonce = "";
  let discoveryReads = 0;
  let fail = false;
  let discoveryFailure = false;
  let invalid = false;
  let pause:
    | {
        started: ReturnType<typeof Promise.withResolvers<void>>;
        gate: ReturnType<typeof Promise.withResolvers<void>>;
      }
    | undefined;
  const revoked: string[] = [];
  const failures: string[] = [];
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
      const idToken = await new SignJWT({ nonce })
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
      res.end("{}");
    } else res.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No address");
  issuer = `http://127.0.0.1:${address.port}`;
  const { store, rows } = memoryStore();
  const construct = () =>
    createBrowserSession({
      issuer,
      origin,
      clientId: "web-client",
      clientSecret: "secret",
      secret,
      resource,
      scopes: ["notes:read"],
      store,
      cookie: { name: "notes" },
      verifyToken: async () => ({
        subject: "owner",
        scopes: ["notes:read"],
        actor: { kind: "client", clientId: "web-client" },
      }),
      onFailure: (operation) => {
        failures.push(operation);
      },
    });
  const auth = construct();
  const beginLogin = async () => {
    const result = await auth.login(
      request("/auth/login", "POST", undefined, { returnTo: "/#board" }),
    );
    assert.equal(result.status, 200, await result.clone().text());
    const authorization = new URL(((await result.json()) as { url: string }).url);
    assert.equal(authorization.searchParams.get("resource"), resource);
    assert.equal(authorization.searchParams.get("scope"), "openid offline_access notes:read");
    assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
    nonce = authorization.searchParams.get("nonce") ?? "";
    const transaction = result.headers.get("set-cookie")?.split(";")[0];
    assert(transaction);
    assert(transaction.startsWith("notes_login="));
    return {
      transaction,
      callbackUrl: `/auth/callback?code=test&iss=${encodeURIComponent(issuer)}&state=${authorization.searchParams.get("state")}`,
    };
  };
  const login = async () => {
    const { transaction, callbackUrl } = await beginLogin();
    const callback = await auth.callback(request(callbackUrl, "GET", transaction));
    assert.equal(callback.status, 302, await callback.text());
    assert.equal(callback.headers.get("referrer-policy"), "no-referrer");
    assert.equal(callback.headers.get("location"), `${origin}/#board`);
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
      failures,
      issuer,
      failRefresh: (failed = true) => {
        fail = failed;
      },
      failDiscovery: (failed) => {
        discoveryFailure = failed;
      },
    });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
};
const unauthorized = async (action: Promise<unknown>) => {
  await assert.rejects(
    action,
    (error) => error instanceof AuthError && error.code === "unauthorized",
  );
};

test("login seals storage, refreshes once concurrently, survives restart, and logs out", () =>
  withFixture(async ({ auth, login, tokenRequests, rows, restart, issuer }) => {
    const cookie = await login();
    assert(auth.hasCookie(request("/api", "GET", cookie)));
    assert(!auth.hasCookie(request("/api")));
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
    assert.equal(await restart().accessToken(request("/api", "GET", cookie)), "second-access");
    const session = await auth.session(request("/auth/session", "GET", cookie));
    assert.equal(session.status, 200);
    assert.deepEqual(await session.json(), {
      authenticated: true,
      subject: "owner",
      scopes: ["notes:read"],
      issuer,
    });
    const logout = await auth.logout(request("/auth/logout", "POST", cookie));
    assert.equal(logout.status, 204);
    assert.match(logout.headers.get("set-cookie") ?? "", /^notes_session=; .*Max-Age=0/u);
    await unauthorized(auth.accessToken(request("/api", "GET", cookie)));
  }));

test("ambiguous refresh failure invalidates the session even after recovery and restart", () =>
  withFixture(async ({ auth, login, tokenRequests, failRefresh, restart, rows, failures }) => {
    const cookie = await login();
    failRefresh();
    assert.equal((await auth.session(request("/auth/session", "GET", cookie))).status, 401);
    assert.deepEqual(failures, ["browser.refresh"]);
    failRefresh(false);
    assert.equal((await auth.session(request("/auth/session", "GET", cookie))).status, 401);
    assert.equal((await restart().session(request("/auth/session", "GET", cookie))).status, 401);
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
    assert.equal((await restart().session(request("/auth/session", "GET", cookie))).status, 401);
    assert.equal(tokenRequests.length, 1);
    assert.equal(rows.size, 0);
  }));

test("discovery failure before refresh remains retryable", () =>
  withFixture(async ({ login, tokenRequests, restart, failDiscovery, rows }) => {
    const cookie = await login();
    const auth = restart();
    failDiscovery(true);
    assert.equal((await auth.session(request("/auth/session", "GET", cookie))).status, 503);
    assert.equal(tokenRequests.length, 1);
    assert.equal(rows.size, 1);
    failDiscovery(false);
    assert.equal((await auth.session(request("/auth/session", "GET", cookie))).status, 200);
    assert.equal(tokenRequests.length, 2);
  }));

test("cross-origin mutations, unbound callbacks and bad return destinations are rejected", () =>
  withFixture(async ({ auth }) => {
    const rejected = await auth.login(
      new Request(`${origin}/auth/login`, {
        method: "POST",
        headers: { origin: "https://evil.example" },
        body: JSON.stringify({ returnTo: "/" }),
      }),
    );
    assert.equal(rejected.status, 403);
    assert.equal(
      (await auth.callback(request("/auth/callback?code=stolen&state=unknown"))).headers.get(
        "location",
      ),
      `${origin}/?auth_error=login_failed`,
    );
    for (const returnTo of ["//evil.example", "/auth/callback", "https://evil.example/", "board"])
      assert.equal(
        (await auth.login(request("/auth/login", "POST", undefined, { returnTo }))).status,
        400,
        returnTo,
      );
    assert.equal((await auth.session(request("/auth/session"))).status, 401);
    for (const body of ["{}", "invalid", JSON.stringify({ returnTo: "http://[invalid" })]) {
      const invalid = new Request(`${origin}/auth/login`, {
        method: "POST",
        headers: { origin },
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
    const logout = auth.logout(request("/auth/logout", "POST", cookie));
    gate.release();
    assert.equal(await refresh, "second-access");
    assert.equal((await logout).status, 204);
    assert.deepEqual(revoked, ["second-refresh"]);
    await unauthorized(auth.accessToken(request("/api", "GET", cookie)));
  }));

test("invalid refresh grants remove the local session without reporting a failure", () =>
  withFixture(async ({ auth, login, invalidateRefresh, rows, failures }) => {
    const cookie = await login();
    invalidateRefresh();
    await unauthorized(auth.accessToken(request("/api", "GET", cookie)));
    assert.equal(rows.size, 0);
    assert.deepEqual(failures, []);
  }));

test("streamed login bodies stop at 16 KiB before discovery or persistence", () =>
  withFixture(async ({ auth, rows, discoveryReads }) => {
    const init = {
      method: "POST",
      headers: { origin },
      duplex: "half" as const,
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(10_000));
          controller.enqueue(new Uint8Array(10_000));
          controller.close();
        },
      }),
    };
    const response = await auth.login(new Request(`${origin}/auth/login`, init));
    assert.equal(response.status, 413);
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(discoveryReads(), 0);
    assert.equal(rows.size, 0);
  }));
