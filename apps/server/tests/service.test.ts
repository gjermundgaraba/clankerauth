import { afterEach, beforeEach, describe, expect, test, vi } from "vite-plus/test";
import { setImmediate } from "node:timers/promises";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import { createLocalJWKSet, jwtVerify } from "jose";
import { requestToResourceInput, verifyAccessTokenRequest } from "better-auth/oauth2";
import { application } from "../src/app.ts";
import { initialize, openAuth, type Service } from "../src/auth.ts";
import { validateSettings, type Settings } from "../src/config.ts";

const password = "test-only owner password 8rS!";
const email = "owner@example.internal";
const resourceA = "https://okf.internal/mcp";
const resourceB = "https://reports.internal/api";
let service: Service;
let handle: ReturnType<typeof application>;
let applications: ReturnType<typeof application>[];
function createApplication() {
  const app = application(service);
  applications.push(app);
  return app;
}
let directory: string;
let settings: Settings;
let cookies: Map<string, string>;

async function request(
  path: string,
  body?: unknown,
  options: { anonymous?: boolean; form?: boolean; origin?: string; authorization?: string } = {},
) {
  const headers = new Headers({
    origin: options.origin ?? settings.baseURL,
    "x-clankerauth-peer": "127.0.0.1",
  });
  if (options.authorization) headers.set("authorization", options.authorization);
  if (!options.anonymous)
    headers.set("cookie", [...cookies].map(([k, v]) => `${k}=${v}`).join("; "));
  if (body)
    headers.set(
      "content-type",
      options.form ? "application/x-www-form-urlencoded" : "application/json",
    );
  const response = await handle(
    new Request(new URL(path, settings.baseURL), {
      method: body ? "POST" : "GET",
      headers,
      body: body
        ? options.form
          ? new URLSearchParams(body as Record<string, string>).toString()
          : JSON.stringify(body)
        : undefined,
    }),
  );
  if (!options.anonymous)
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      cookies.set(pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1));
    }
  return response;
}
async function login(pass = password) {
  return request("/api/auth/sign-in/email", { email, password: pass });
}
const resourceFixtures = [
  { identifier: resourceA, name: "OKF MCP", scopes: ["okf:read", "okf:write"] },
  { identifier: resourceB, name: "Reports", scopes: ["reports:read"] },
];
async function createResourceFixtures() {
  const listing = await (await request("/admin/clients")).json();
  for (const resource of resourceFixtures) {
    if (
      listing.resources.some(
        (row: { identifier: string }) => row.identifier === resource.identifier,
      )
    )
      continue;
    const response = await request("/admin/resources", resource);
    expect(response.status, await response.clone().text()).toBe(201);
  }
}
async function client(resource = resourceA, confidential = false) {
  await createResourceFixtures();
  const response = await request("/admin/clients", {
    name: "Test application",
    redirect: "http://127.0.0.1:9876/callback",
    resources: [resource],
    native: true,
    confidential,
  });
  expect(response.status, await response.clone().text()).toBe(201);
  return response.json();
}
function authorization(clientId: string, resource = resourceA, extra: Record<string, string> = {}) {
  const verifier = randomBytes(32).toString("base64url");
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: "http://127.0.0.1:9876/callback",
    response_type: "code",
    scope: "openid offline_access okf:read",
    resource,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state: "state-to-validate",
    prompt: "consent",
    ...extra,
  });
  return { verifier, path: `/api/auth/oauth2/authorize?${query}` };
}
async function authorize(clientId: string, resource = resourceA, scope?: string) {
  const flow = authorization(
    clientId,
    resource,
    scope
      ? { scope }
      : resource === resourceB
        ? { scope: "openid offline_access reports:read" }
        : {},
  );
  const response = await request(flow.path);
  expect(response.status, await response.clone().text()).toBe(302);
  const location = new URL(response.headers.get("location")!, settings.baseURL);
  expect(location.pathname).toBe("/consent");
  const result = await request("/api/auth/oauth2/consent", {
    accept: true,
    oauth_query: location.search.slice(1),
  });
  expect(result.status, await result.clone().text()).toBe(200);
  const redirect = new URL((await result.json()).url);
  expect(redirect.searchParams.get("state")).toBe("state-to-validate");
  expect(redirect.searchParams.get("iss")).toBe(`${settings.baseURL}/api/auth`);
  return { code: redirect.searchParams.get("code")!, verifier: flow.verifier };
}
async function tokens(
  clientId: string,
  resource = resourceA,
  authorization?: string,
  scope?: string,
) {
  const grant = await authorize(clientId, resource, scope);
  const response = await request(
    "/api/auth/oauth2/token",
    {
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: "http://127.0.0.1:9876/callback",
      code: grant.code,
      code_verifier: grant.verifier,
      resource,
    },
    { anonymous: true, form: true, authorization },
  );
  expect(response.status, await response.clone().text()).toBe(200);
  return response.json();
}

beforeEach(async () => {
  applications = [];
  directory = mkdtempSync(join(tmpdir(), "clankerauth-"));
  settings = validateSettings({
    baseURL: "http://localhost:3000",
    secret: randomBytes(32).toString("hex"),
    database: join(directory, "auth.sqlite"),
    host: "127.0.0.1",
    port: 3000,
  });
  service = openAuth(settings);
  await initialize(service);
  handle = createApplication();
  cookies = new Map();
});
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(applications.map((app) => app.dispose()));
  await service.close();
  rmSync(directory, { recursive: true, force: true });
});

async function setupOwner() {
  const response = await request("/api/setup", { email, password });
  expect(response.status, await response.clone().text()).toBe(201);
}

async function restart() {
  await service.close();
  service = openAuth(settings);
  await initialize(service);
  handle = createApplication();
}

describe("first-run setup", () => {
  test("fresh startup and restart permit setup, which creates no session and closes permanently", async () => {
    expect(await (await request("/api/setup")).json()).toEqual({ required: true });
    await restart();
    const status = await request("/api/setup");
    expect(await status.json()).toEqual({ required: true });
    expect(status.headers.get("cache-control")).toContain("no-store");
    expect((await request("/admin/clients")).status).toBe(401);
    expect(
      (await request("/api/auth/sign-up/email", { email, password, name: "Owner" })).status,
    ).toBe(404);
    await expect(
      service.auth.api.signUpEmail({ body: { email, password, name: "Owner" } }),
    ).rejects.toThrow();

    const created = await request("/api/setup", { email: "Owner@Example.Internal", password });
    expect(created.status, await created.clone().text()).toBe(201);
    expect(await created.json()).toEqual({ created: true });
    expect(created.headers.getSetCookie()).toEqual([]);
    expect(service.db.prepare("SELECT count(*) AS n FROM session").get()).toEqual({ n: 0 });
    expect(service.db.prepare("SELECT name, email, emailVerified FROM user").get()).toEqual({
      name: "Owner",
      email,
      emailVerified: 0,
    });
    const owner = service.owner();
    expect(owner).toBeTypeOf("string");
    expect(await (await request("/api/setup")).json()).toEqual({ required: false });
    expect((await request("/admin/clients")).status).toBe(401);
    expect((await login()).status).toBe(200);
    await restart();
    expect(service.owner()).toBe(owner);
    expect(await (await request("/api/setup")).json()).toEqual({ required: false });
    expect((await request("/admin/clients")).status).toBe(200);
    expect((await request("/api/setup", { email, password })).status).toBe(409);
  });

  test("invalid setup input, origin, and encoding never create an account", async () => {
    for (const body of [
      {},
      null,
      [],
      { email: "invalid", password },
      { email: ".owner@example.internal", password },
      { email: "owner..name@example.internal", password },
      { email: "owner@example.123", password },
      { email, password: "x".repeat(7) },
      { email, password: "x".repeat(129) },
      { email: 42, password },
      { email, password: 42 },
    ]) {
      const response = await handle(
        new Request(`${settings.baseURL}/api/setup`, {
          method: "POST",
          headers: { origin: settings.baseURL, "content-type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
      expect(response.status, await response.clone().text()).toBe(400);
    }
    for (const origin of [undefined, "https://evil.example", `${settings.baseURL}/`]) {
      const headers = new Headers({ "content-type": "application/json" });
      if (origin !== undefined) headers.set("origin", origin);
      const response = await handle(
        new Request(`${settings.baseURL}/api/setup`, {
          method: "POST",
          headers,
          body: JSON.stringify({ email, password }),
        }),
      );
      expect(response.status).toBe(403);
    }
    for (const [contentType, body] of [
      ["application/json", "{"],
      ["text/plain", JSON.stringify({ email, password })],
      ["application/x-www-form-urlencoded", new URLSearchParams({ email, password }).toString()],
    ]) {
      const response = await handle(
        new Request(`${settings.baseURL}/api/setup`, {
          method: "POST",
          headers: { origin: settings.baseURL, "content-type": contentType! },
          body,
        }),
      );
      expect(response.status).toBe(400);
      expect(await response.text()).not.toContain(password);
    }
    expect(service.db.prepare("SELECT count(*) AS n FROM user").get()).toEqual({ n: 0 });
    expect(service.owner()).toBeUndefined();
    await setupOwner();
  });

  test("simultaneous submissions create exactly one owner", async () => {
    const responses = await Promise.all([
      request("/api/setup", { email, password }),
      request("/api/setup", { email: "second@example.internal", password }),
    ]);
    expect(responses.map((response) => response.status).sort((a, b) => a - b)).toEqual([201, 409]);
    for (const table of ["user", "account", "serviceOwner"])
      expect(service.db.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toEqual({ n: 1 });
    expect(service.db.prepare("SELECT count(*) AS n FROM session").get()).toEqual({ n: 0 });
  });

  test("a failed owner-marker insert rolls back all account writes and permits retry", async () => {
    service.db.exec(`CREATE TRIGGER fail_setup BEFORE INSERT ON serviceOwner
      BEGIN SELECT RAISE(ABORT, 'Injected owner-marker failure'); END`);
    const failed = await request("/api/setup", { email, password });
    expect(failed.status).toBe(500);
    const error = await failed.text();
    expect(error).not.toContain(password);
    expect(error).not.toContain("Injected owner-marker failure");
    for (const table of ["user", "account", "serviceOwner", "session"])
      expect(service.db.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toEqual({ n: 0 });
    expect(await (await request("/api/setup")).json()).toEqual({ required: true });
    service.db.exec("DROP TRIGGER fail_setup");
    await setupOwner();
    expect((await login()).status).toBe(200);
  });

  test("startup rejects an existing account without an owner marker", async () => {
    service.db
      .prepare(
        "INSERT INTO user (id, name, email, emailVerified, createdAt, updatedAt) VALUES (?, ?, ?, 0, ?, ?)",
      )
      .run("orphan", "Orphan", email, Date.now(), Date.now());
    await service.close();
    service = openAuth(settings);
    await expect(initialize(service)).rejects.toThrow();
    expect(service.db.prepare("SELECT id FROM user").all()).toEqual([{ id: "orphan" }]);
    expect(service.owner()).toBeUndefined();
  });
});

describe("owner boundary", () => {
  beforeEach(setupOwner);
  test("shutdown drains admitted work even after its HTTP client disconnects", async () => {
    const admitted = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let work: Promise<unknown> | undefined;
    const server = createServer((_incoming, outgoing) => {
      work = service.exclusive(async () => {
        admitted.resolve();
        await release.promise;
        return service.db.prepare("SELECT 1 AS value").get();
      });
      void work.then(() => outgoing.end());
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Missing test address");
    const connection = httpRequest(`http://127.0.0.1:${address.port}`);
    connection.on("error", () => {}); // Expected local abort, after admission is observed.
    connection.end();
    await admitted.promise;
    connection.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const closing = service.close();
    try {
      await expect(service.exclusive(async () => 0)).rejects.toThrow("Service stopping");
      await setImmediate();
      expect(service.db.open).toBe(true);
    } finally {
      release.resolve();
      await closing;
    }
    expect(await work).toEqual({ value: 1 });
    expect(service.db.open).toBe(false);
    expect((await request("/healthz")).status).toBe(503);
  });

  test("serves the built web workspace rather than the server working directory", async () => {
    for (const path of ["/", "/setup", "/login", "/consent"]) {
      const response = await request(path);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("text/html");
      const html = await response.text();
      expect(html).toContain("<title>Clanker Auth</title>");
      const assets = [...html.matchAll(/(?:src|href)="(\/assets\/[^" ]+)"/g)];
      expect(assets).toHaveLength(2);
      for (const [, asset] of assets) {
        const result = await request(asset!);
        expect(result.status).toBe(200);
        expect(result.headers.get("content-type")).toBe(
          asset!.endsWith(".js") ? "text/javascript" : "text/css",
        );
        expect((await result.text()).length).toBeGreaterThan(100);
      }
    }
    expect((await request("/src/main.ts")).status).toBe(404);
  });

  test("configuration rejects insecure issuers and empty secrets", () => {
    for (const baseURL of [
      "http://auth.internal",
      "https://auth.internal/",
      "https://auth.internal/path",
      "https://user:pass@auth.internal",
    ]) {
      expect(() => validateSettings({ ...settings, baseURL })).toThrow();
    }
    expect(() => validateSettings({ ...settings, secret: "" })).toThrow();
    expect(validateSettings({ ...settings, baseURL: "https://auth.internal" }).baseURL).toBe(
      "https://auth.internal",
    );
  });

  test("login throttles brute force without exposing passwords", async () => {
    for (let i = 0; i < 5; i++) expect((await login("deliberately incorrect")).status).toBe(401);
    const limited = await login();
    expect(limited.status).toBe(429);
    expect(await limited.text()).not.toContain(password);
  });

  test("closed signup, protected admin, CSRF, credential login and logout", async () => {
    expect((await request("/admin/clients")).status).toBe(401);
    expect(
      (
        await request("/api/auth/sign-up/email", {
          email: "stranger@example.internal",
          password,
          name: "Intruder",
        })
      ).status,
    ).toBe(404);
    await expect(
      service.auth.api.signUpEmail({
        body: { email: "stranger@example.internal", password, name: "Intruder" },
      }),
    ).rejects.toThrow();
    expect((await login("incorrect password")).status).toBe(401);
    const signedIn = await login();
    expect(signedIn.status).toBe(200);
    expect(signedIn.headers.getSetCookie().join(";")).toContain("HttpOnly");
    const session = await request("/api/auth/get-session");
    expect(session.status).toBe(200);
    expect((await session.json()).user.id).toBe(service.owner());
    expect(session.headers.has("set-auth-jwt")).toBe(false);
    expect((await request("/admin/clients")).status).toBe(200);
    expect((await request("/admin/clients", {}, { origin: "https://evil.example" })).status).toBe(
      403,
    );
    expect(
      (await request("/api/auth/oauth2/create-client", { redirect_uris: ["https://evil.example"] }))
        .status,
    ).toBe(404);
    expect(
      (await request("/api/auth/oauth2/register", { redirect_uris: ["https://evil.example"] }))
        .status,
    ).toBe(404);
    expect((await request("/api/auth/token")).status).toBe(404);
    expect((await request("/api/auth/sign-out", {})).status).toBe(200);
    expect((await request("/admin/clients")).status).toBe(401);
  });

  test("existing non-owner credentials, sessions, codes and grants cannot convey authority", async () => {
    await login();
    const ownerId = service.owner()!;
    const app = await client(resourceA, true);
    service.db
      .prepare(
        "INSERT INTO user (id, name, email, emailVerified, createdAt, updatedAt) VALUES (?, ?, ?, 0, ?, ?)",
      )
      .run("other", "Other", "other@example.internal", Date.now(), Date.now());
    service.db
      .prepare(
        "INSERT INTO account (id, accountId, providerId, userId, password, createdAt, updatedAt) SELECT 'other-account', 'other', providerId, 'other', password, createdAt, updatedAt FROM account WHERE userId = ? AND providerId = 'credential'",
      )
      .run(ownerId);
    // Seed genuinely issued legacy state, then make that identity ineligible.
    service.db.prepare("UPDATE serviceOwner SET userId = 'other'").run();
    cookies.clear();
    expect(
      (await request("/api/auth/sign-in/email", { email: "other@example.internal", password }))
        .status,
    ).toBe(200);
    const flow = authorization(app.client_id);
    const consentResponse = await request(flow.path);
    const signedQuery = new URL(
      consentResponse.headers.get("location")!,
      settings.baseURL,
    ).search.slice(1);
    const grant = await authorize(app.client_id);
    const publicApp = await client(resourceA, true);
    const publicBasic = `Basic ${Buffer.from(`${publicApp.client_id}:${publicApp.client_secret}`).toString("base64")}`;
    const issued = await tokens(publicApp.client_id, resourceA, publicBasic);
    for (const token of [issued.access_token, issued.refresh_token]) {
      const active = await request(
        "/api/auth/oauth2/introspect",
        { token, client_id: publicApp.client_id },
        { anonymous: true, form: true, authorization: publicBasic },
      );
      expect((await active.json()).active).toBe(true);
    }
    expect(
      (
        await request("/api/auth/oauth2/userinfo", undefined, {
          anonymous: true,
          authorization: `Bearer ${issued.access_token}`,
        })
      ).status,
    ).toBe(200);
    service.db.prepare("UPDATE serviceOwner SET userId = ?").run(ownerId);
    const before = service.db.prepare("SELECT count(*) AS n FROM oauthRefreshToken").get();
    expect(
      (
        await request(
          "/api/auth/sign-in/email",
          { email: "other@example.internal", password },
          { anonymous: true },
        )
      ).status,
    ).toBe(401);
    expect(
      (
        await request(
          "/api/auth/sign-in/email",
          { email: "other@example.internal", password, oauth_query: signedQuery },
          { anonymous: true },
        )
      ).status,
    ).toBe(401);
    expect((await request("/admin/clients")).status).toBe(401);
    expect((await request("/api/auth/get-session")).status).toBe(401);
    expect((await request(flow.path)).status).toBe(401);
    for (const path of ["/oauth2/consent", "/oauth2/continue"]) {
      expect(
        (await request(`/api/auth${path}`, { accept: true, oauth_query: signedQuery })).status,
      ).toBe(401);
    }
    expect(
      (
        await request("/api/auth/change-password", {
          currentPassword: password,
          newPassword: "not an authorized change 123!",
        })
      ).status,
    ).toBe(401);
    const basic = `Basic ${Buffer.from(`${app.client_id}:${app.client_secret}`).toString("base64")}`;
    const exchange = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "authorization_code",
        client_id: app.client_id,
        code: grant.code,
        code_verifier: grant.verifier,
        redirect_uri: "http://127.0.0.1:9876/callback",
        resource: resourceA,
      },
      { anonymous: true, form: true, authorization: basic },
    );
    expect(exchange.status).toBe(400);
    expect((await exchange.json()).error).toBe("invalid_grant");
    for (const form of [true, false]) {
      const refresh = await request(
        "/api/auth/oauth2/token",
        {
          grant_type: "refresh_token",
          client_id: publicApp.client_id,
          refresh_token: issued.refresh_token,
          resource: resourceA,
        },
        { anonymous: true, form, authorization: publicBasic },
      );
      expect(refresh.status).toBe(form ? 400 : 415);
      if (form) expect((await refresh.json()).error).toBe("invalid_grant");
    }
    for (const body of [undefined, { access_token: issued.access_token }]) {
      expect(
        (
          await request("/api/auth/oauth2/userinfo", body, {
            anonymous: true,
            form: true,
            authorization: body ? undefined : `Bearer ${issued.access_token}`,
          })
        ).status,
      ).toBe(401);
    }
    // Introspection uses public subjects; test both refresh and JWT paths.
    for (const token of [issued.access_token, issued.refresh_token]) {
      const introspection = await request(
        "/api/auth/oauth2/introspect",
        { token, client_id: publicApp.client_id },
        { anonymous: true, form: true, authorization: publicBasic },
      );
      expect(introspection.status).toBe(200);
      expect(await introspection.json()).toEqual({ active: false });
    }
    expect(service.db.prepare("SELECT count(*) AS n FROM oauthRefreshToken").get()).toEqual(before);
    // A denied legacy cookie must not block sign-out and subsequent owner login.
    expect((await request("/api/auth/sign-out", {})).status).toBe(200);
    const sessionless = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "refresh_token",
        client_id: publicApp.client_id,
        refresh_token: issued.refresh_token,
        resource: resourceA,
      },
      { anonymous: true, form: true, authorization: publicBasic },
    );
    expect(sessionless.status).toBe(400);
    expect((await sessionless.json()).error).toBe("invalid_grant");
    expect((await login()).status).toBe(200);
    expect((await request("/admin/clients")).status).toBe(200);
    const ownerApp = await client();
    expect((await tokens(ownerApp.client_id)).access_token).toBeTypeOf("string");
  });
});

describe("OAuth boundaries and lifecycle", () => {
  beforeEach(setupOwner);
  test.each(["replay", "revoke", "delete", "unlink", "remove scope"])(
    "concurrent refresh and %s cannot leave the winning replacement usable",
    async (action) => {
      await login();
      const app = await client();
      const unrelated = await client(resourceB);
      const unaffected = await tokens(unrelated.client_id, resourceB);
      const original = await tokens(app.client_id);
      const refresh = (token: string) =>
        request(
          "/api/auth/oauth2/token",
          {
            grant_type: "refresh_token",
            client_id: app.client_id,
            refresh_token: token,
            resource: resourceA,
          },
          { form: true, anonymous: true },
        );
      const context = await service.auth.$context;
      const increment = context.adapter.incrementOne.bind(context.adapter);
      const reached = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      const queued = Promise.withResolvers<void>();
      const exclusive = service.exclusive;
      let attempts = 0;
      let started = 0;
      vi.spyOn(service, "exclusive").mockImplementation((operation) => {
        const result = exclusive(() => {
          started++;
          return operation();
        });
        if (++attempts === 2) queued.resolve();
        return result;
      });
      let rotations = 0;
      vi.spyOn(context.adapter, "incrementOne").mockImplementation(async (input) => {
        if (input.model === "oauthRefreshToken" && ++rotations === 1) {
          reached.resolve();
          await release.promise;
        }
        return increment(input);
      });
      const first = refresh(original.refresh_token);
      await reached.promise; // First request has read the unrevoked row but has not run its CAS.
      handle = createApplication(); // Even separate HTTP wrappers must share admission.
      const second =
        action === "replay"
          ? refresh(original.refresh_token)
          : action === "revoke"
            ? request(
                "/api/auth/oauth2/revoke",
                { token: original.refresh_token, client_id: app.client_id },
                { anonymous: true, form: true },
              )
            : action === "unlink"
              ? request("/admin/clients/access", { client_id: app.client_id, resources: [] })
              : action === "remove scope"
                ? request("/admin/resources/update", {
                    identifier: resourceA,
                    name: "MCP",
                    scopes: ["okf:write"],
                  })
                : request("/admin/clients/delete", { client_id: app.client_id });
      await queued.promise;
      try {
        expect(started).toBe(1); // Second request cannot read the same unrevoked row.
      } finally {
        release.resolve();
        await Promise.all([first, second]);
      }
      const responses = await Promise.all([first, second]);
      // Provider 1.7.3 invalidates the family but returns 400 for revoked-token revocation.
      expect(responses.map((r) => r.status)).toEqual([
        200,
        ["delete", "unlink", "remove scope"].includes(action) ? 200 : 400,
      ]);
      const winner = await responses[0]!.json();
      expect((await refresh(winner.refresh_token)).status).toBe(400);
      expect(
        service.db
          .prepare("SELECT count(*) AS n FROM oauthRefreshToken WHERE clientId = ?")
          .get(app.client_id),
      ).toEqual({ n: 0 });
      const otherRefresh = await request(
        "/api/auth/oauth2/token",
        {
          grant_type: "refresh_token",
          client_id: unrelated.client_id,
          refresh_token: unaffected.refresh_token,
          resource: resourceB,
        },
        { anonymous: true, form: true },
      );
      expect(otherRefresh.status).toBe(200);
    },
  );

  test("signing failure drains refresh writes before queued revocation", async () => {
    await login();
    const app = await client();
    const original = await tokens(app.client_id);
    const context = await service.auth.$context;
    const create = context.adapter.create.bind(context.adapter);
    const findMany = context.adapter.findMany.bind(context.adapter);
    const reached = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const signingFailed = Promise.withResolvers<void>();
    vi.spyOn(context.adapter, "create").mockImplementation(async (input) => {
      if (input.model === "oauthRefreshToken") {
        reached.resolve();
        await release.promise; // Parent CAS succeeded; replacement is not yet stored.
      }
      return create(input);
    });
    const signing = vi.spyOn(context.adapter, "findMany").mockImplementation(async (input) => {
      if (input.model === "jwks") {
        await reached.promise;
        signingFailed.resolve();
        throw new Error("Injected signing-key read failure");
      }
      return findMany(input);
    });
    let completed = false;
    const first = request(
      "/api/auth/oauth2/token",
      {
        grant_type: "refresh_token",
        client_id: app.client_id,
        refresh_token: original.refresh_token,
        resource: resourceA,
      },
      { anonymous: true, form: true },
    ).then((response) => {
      completed = true;
      return response;
    });
    await signingFailed.promise;
    await setImmediate(); // Drain the known rejection's microtask chain, without releasing the write.
    const second = request(
      "/api/auth/oauth2/revoke",
      { token: original.refresh_token, client_id: app.client_id },
      { anonymous: true, form: true },
    );
    const escaped = completed;
    release.resolve();
    const responses = await Promise.all([first, second]);
    expect(escaped).toBe(false);
    expect(responses.map((response) => response.status)).toEqual([500, 400]);
    expect(
      service.db
        .prepare("SELECT count(*) AS n FROM oauthRefreshToken WHERE clientId = ?")
        .get(app.client_id),
    ).toEqual({ n: 0 });
    signing.mockRestore();
    expect((await tokens(app.client_id)).access_token).toBeTypeOf("string");
  });

  test("confidential Basic authentication, rotation, introspection, logout and client deletion", async () => {
    await login();
    const app = await client(resourceA, true);
    expect(app.client_secret).toBeTypeOf("string");
    const listing = await (await request("/admin/clients")).json();
    expect(JSON.stringify(listing)).not.toContain(app.client_secret);
    const grant = await authorize(app.client_id);
    const basic = (secret: string) =>
      `Basic ${Buffer.from(`${app.client_id}:${secret}`).toString("base64")}`;
    const exchange = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "authorization_code",
        client_id: app.client_id,
        redirect_uri: "http://127.0.0.1:9876/callback",
        code: grant.code,
        code_verifier: grant.verifier,
        resource: resourceA,
      },
      {
        anonymous: true,
        form: true,
        authorization: basic(app.client_secret),
        origin: "https://client.example",
      },
    );
    expect(exchange.status, await exchange.clone().text()).toBe(200);
    expect(exchange.headers.get("access-control-allow-origin")).toBe("*");
    const issued = await exchange.json();
    const introspect = (secret: string) =>
      request(
        "/api/auth/oauth2/introspect",
        { token: issued.access_token },
        { anonymous: true, form: true, authorization: basic(secret) },
      );
    expect((await (await introspect(app.client_secret)).json()).active).toBe(true);
    const rotated = await (
      await request("/admin/clients/rotate", { client_id: app.client_id })
    ).json();
    expect(rotated.client_secret).toBeTypeOf("string");
    expect(rotated.client_secret).not.toBe(app.client_secret);
    expect((await introspect(app.client_secret)).status).toBe(401);
    expect((await (await introspect(rotated.client_secret)).json()).active).toBe(true);
    await request("/api/auth/sign-out", {});
    expect((await (await introspect(rotated.client_secret)).json()).active).toBe(false);
    await login();
    expect((await request("/admin/clients/delete", { client_id: app.client_id })).status).toBe(200);
    expect((await (await request("/admin/clients")).json()).clients).toEqual([]);
    const refresh = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "refresh_token",
        client_id: app.client_id,
        refresh_token: issued.refresh_token,
        resource: resourceA,
      },
      { anonymous: true, form: true, authorization: basic(rotated.client_secret) },
    );
    expect(refresh.status, await refresh.clone().text()).toBe(400);
    expect((await refresh.json()).error).toBe("invalid_grant");
  });

  test("discovery pins issuer and advertises S256, no registration or machine grants", async () => {
    for (const path of [
      "/.well-known/oauth-authorization-server/api/auth",
      "/api/auth/.well-known/oauth-authorization-server",
      "/api/auth/.well-known/openid-configuration",
    ]) {
      const response = await request(path);
      expect(response.status, await response.clone().text()).toBe(200);
      const metadata = await response.json();
      expect(metadata.issuer).toBe(`${settings.baseURL}/api/auth`);
      expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
      expect(metadata.registration_endpoint).toBeUndefined();
      expect(metadata.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    }
  });

  test("login continuation and signed consent denial; altered consent is rejected", async () => {
    await login();
    const app = await client();
    cookies.clear();
    const flow = authorization(app.client_id);
    const response = await request(flow.path);
    const location = new URL(response.headers.get("location")!, settings.baseURL);
    expect(location.pathname).toBe("/login");
    const signedIn = await request("/api/auth/sign-in/email", {
      email,
      password,
      oauth_query: location.search.slice(1),
    });
    expect(signedIn.status, await signedIn.clone().text()).toBe(200);
    const continued = new URL((await signedIn.json()).url, settings.baseURL);
    expect(continued.pathname).toBe("/consent");
    const tampered = new URL(continued);
    tampered.searchParams.set("resource", resourceB);
    expect(
      (
        await request("/api/auth/oauth2/consent", {
          accept: true,
          oauth_query: tampered.search.slice(1),
        })
      ).status,
    ).toBe(400);
    const denied = await request("/api/auth/oauth2/consent", {
      accept: false,
      oauth_query: continued.search.slice(1),
    });
    expect(denied.status).toBe(200);
    const result = new URL((await denied.json()).url);
    expect(result.searchParams.get("error")).toBe("access_denied");
    expect(result.searchParams.get("code")).toBeNull();
  });

  test("S256, redirect matching, single-resource and per-client audience enforcement", async () => {
    await login();
    const app = await client();
    const invalidRequests: Record<string, string>[] = [
      { code_challenge_method: "plain" },
      { redirect_uri: "http://127.0.0.1:9876/evil" },
      { resource: resourceB },
      { resource: "" },
    ];
    for (const extra of invalidRequests) {
      const response = await request(authorization(app.client_id, resourceA, extra).path);
      const text = await response.text();
      expect(
        response.status >= 400 || response.headers.get("location")?.includes("error="),
        text,
      ).toBeTruthy();
    }
    const missing = await request(
      "/api/auth/oauth2/token",
      { grant_type: "refresh_token" },
      { form: true },
    );
    expect((await missing.json()).error).toBe("invalid_target");
    const multiple = await request(
      `${authorization(app.client_id).path}&resource=${encodeURIComponent(resourceB)}`,
    );
    expect((await multiple.json()).error).toBe("invalid_target");
    const grant = await authorize(app.client_id);
    const wrongVerifier = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "authorization_code",
        client_id: app.client_id,
        redirect_uri: "http://127.0.0.1:9876/callback",
        code: grant.code,
        code_verifier: "x".repeat(43),
        resource: resourceA,
      },
      { form: true, anonymous: true },
    );
    expect(wrongVerifier.status).toBe(401);
    expect((await wrongVerifier.json()).error).toBe("invalid_request");
  });

  test("JWT signature, issuer, scopes, expiry and audience separation survive restart", async () => {
    await login();
    const a = await client();
    const b = await client(resourceB);
    const tokenA = await tokens(a.client_id);
    const tokenB = await tokens(b.client_id, resourceB);
    const jwks = await (await request("/api/auth/jwks")).json();
    const keys = createLocalJWKSet(jwks);
    const keyServer = createServer((_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(jwks));
    });
    await new Promise<void>((resolve) => keyServer.listen(0, "127.0.0.1", resolve));
    try {
      const address = keyServer.address();
      if (!address || typeof address === "string")
        throw new Error("Missing test key-server address");
      const verify = (scope: string, audience = resourceA) =>
        verifyAccessTokenRequest(
          requestToResourceInput(
            new Request(resourceA, { headers: { authorization: `Bearer ${tokenA.access_token}` } }),
          ),
          {
            jwksUrl: `http://127.0.0.1:${address.port}/jwks`,
            verifyOptions: {
              issuer: `${settings.baseURL}/api/auth`,
              audience,
              typ: "at+jwt",
              algorithms: ["EdDSA"],
            },
            requiredScopes: [scope],
          },
        );
      expect((await verify("okf:read")).sub).toBe(service.owner());
      await expect(verify("okf:write")).rejects.toThrow();
      await expect(verify("okf:read", resourceB)).rejects.toThrow();
    } finally {
      await new Promise<void>((resolve) => keyServer.close(() => resolve()));
    }
    const verified = await jwtVerify(tokenA.access_token, keys, {
      issuer: `${settings.baseURL}/api/auth`,
      audience: resourceA,
      typ: "at+jwt",
    });
    // With openid, Better Auth also includes its own UserInfo endpoint, never another downstream API.
    expect(verified.payload.aud).toEqual([
      resourceA,
      `${settings.baseURL}/api/auth/oauth2/userinfo`,
    ]);
    expect(verified.payload.scope).toContain("okf:read");
    expect(verified.payload.exp! - verified.payload.iat!).toBeLessThanOrEqual(300);
    const pieces = tokenA.access_token.split(".");
    pieces[1] = Buffer.from(JSON.stringify({ ...verified.payload, aud: resourceB })).toString(
      "base64url",
    );
    await expect(jwtVerify(pieces.join("."), keys, { audience: resourceB })).rejects.toThrow();
    await expect(
      jwtVerify(tokenA.id_token, keys, { audience: resourceA, typ: "at+jwt" }),
    ).rejects.toThrow();
    await expect(jwtVerify(tokenA.access_token, keys, { audience: resourceB })).rejects.toThrow();
    await expect(
      jwtVerify(tokenA.access_token, keys, { issuer: "https://evil.example" }),
    ).rejects.toThrow();
    await expect(
      jwtVerify(tokenA.access_token, keys, { currentDate: new Date(Date.now() + 301000) }),
    ).rejects.toThrow();
    await expect(jwtVerify(tokenB.access_token, keys, { audience: resourceA })).rejects.toThrow();
    service.db.close();
    service = openAuth(settings);
    await initialize(service);
    handle = createApplication();
    expect(await (await request("/api/auth/jwks")).json()).toEqual(jwks);
    expect((await request("/admin/clients")).status).toBe(200);
    const refresh = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "refresh_token",
        client_id: a.client_id,
        refresh_token: tokenA.refresh_token,
        resource: resourceA,
      },
      { anonymous: true, form: true },
    );
    expect(refresh.status, await refresh.clone().text()).toBe(200);
    await initialize(service);
  });

  test("a rotated token cannot revoke another public client's refresh family", async () => {
    await login();
    const a = await client();
    const b = await client(resourceB);
    const originalA = await tokens(a.client_id);
    const originalB = await tokens(b.client_id, resourceB);
    const refresh = (clientId: string, token: string, resource: string) =>
      request(
        "/api/auth/oauth2/token",
        {
          grant_type: "refresh_token",
          client_id: clientId,
          refresh_token: token,
          resource,
        },
        { anonymous: true, form: true },
      );
    const rotated = await refresh(a.client_id, originalA.refresh_token, resourceA);
    expect(rotated.status).toBe(200);
    const replacementA = await rotated.json();
    const before = service.db
      .prepare(
        "SELECT clientId, count(*) AS n FROM oauthRefreshToken GROUP BY clientId ORDER BY clientId",
      )
      .all();
    const attack = await request(
      "/api/auth/oauth2/revoke",
      {
        client_id: b.client_id,
        token: originalA.refresh_token,
        token_type_hint: "refresh_token",
      },
      { anonymous: true, form: true },
    );
    // A mismatched client is a no-op, before any family invalidation occurs.
    expect(
      service.db
        .prepare(
          "SELECT clientId, count(*) AS n FROM oauthRefreshToken GROUP BY clientId ORDER BY clientId",
        )
        .all(),
    ).toEqual(before);
    expect(attack.status).toBe(200);
    expect((await refresh(b.client_id, originalB.refresh_token, resourceB)).status).toBe(200);
    expect((await refresh(a.client_id, replacementA.refresh_token, resourceA)).status).toBe(200);
  });

  test("refresh is resource-bound, rotates, detects replay, and revokes", async () => {
    await login();
    const app = await client();
    const original = await tokens(app.client_id);
    const refresh = (token: string, resource = resourceA) =>
      request(
        "/api/auth/oauth2/token",
        { grant_type: "refresh_token", client_id: app.client_id, refresh_token: token, resource },
        { form: true, anonymous: true },
      );
    expect((await refresh(original.refresh_token, resourceB)).status).toBe(400);
    const rotatedResponse = await refresh(original.refresh_token);
    expect(rotatedResponse.status, await rotatedResponse.clone().text()).toBe(200);
    const rotated = await rotatedResponse.json();
    expect(rotated.refresh_token).not.toBe(original.refresh_token);
    expect((await refresh(original.refresh_token)).status).toBe(400);
    expect((await refresh(rotated.refresh_token)).status).toBe(400);
    const another = await tokens(app.client_id);
    const revoked = await request(
      "/api/auth/oauth2/revoke",
      { token: another.refresh_token, token_type_hint: "refresh_token", client_id: app.client_id },
      { form: true, anonymous: true },
    );
    expect(revoked.status).toBe(200);
    expect((await refresh(another.refresh_token)).status).toBe(400);
    const jwtRevocation = await request(
      "/api/auth/oauth2/revoke",
      { token: another.access_token, token_type_hint: "access_token", client_id: app.client_id },
      { form: true, anonymous: true },
    );
    expect(jwtRevocation.status).toBe(400);
    expect((await jwtRevocation.json()).error).toBe("unsupported_token_type");
  });
});

describe("dashboard resources and client access", () => {
  beforeEach(async () => {
    await setupOwner();
    expect((await login()).status).toBe(200);
  });

  const listing = async () => (await request("/admin/clients")).json();
  const access = (clientId: string, resources: string[]) =>
    request("/admin/clients/access", { client_id: clientId, resources });
  const updateResource = (identifier: string, scopes: string[], name = "Updated resource") =>
    request("/admin/resources/update", { identifier, name, scopes });
  const exchange = (
    clientId: string,
    grant: { code: string; verifier: string },
    resource: string,
  ) =>
    request(
      "/api/auth/oauth2/token",
      {
        grant_type: "authorization_code",
        client_id: clientId,
        redirect_uri: "http://127.0.0.1:9876/callback",
        code: grant.code,
        code_verifier: grant.verifier,
        resource,
      },
      { anonymous: true, form: true },
    );
  const refresh = (clientId: string, token: string, resource: string) =>
    request(
      "/api/auth/oauth2/token",
      {
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: token,
        resource,
      },
      { anonymous: true, form: true },
    );

  test("a fresh database stays empty across restart; CRUD persists without configuration seeds", async () => {
    expect((await listing()).resources).toEqual([]);
    await restart();
    expect((await listing()).resources).toEqual([]);
    const resource = { identifier: resourceA, name: "Personal MCP", scopes: ["read", "write"] };
    expect((await request("/admin/resources", resource)).status).toBe(201);
    expect((await request("/admin/resources", resource)).status).toBe(409);
    expect((await updateResource(resourceA, ["read"], "Renamed MCP")).status).toBe(200);
    await restart();
    expect((await listing()).resources).toEqual([
      { ...resource, name: "Renamed MCP", scopes: ["read"] },
    ]);
    expect((await request("/admin/resources/delete", { identifier: resourceA })).status).toBe(200);
    await restart();
    expect((await listing()).resources).toEqual([]);
    expect((await updateResource(resourceA, ["read"])).status).toBe(404);
    expect((await request("/admin/resources/delete", { identifier: resourceA })).status).toBe(404);
  });

  test("resource mutations reject invalid input, anonymous, cross-origin and stale sessions", async () => {
    const valid = { identifier: resourceA, name: "MCP", scopes: ["read"] };
    for (const input of [
      { ...valid, identifier: "http://api.internal" },
      { ...valid, identifier: "https://api.internal/#fragment" },
      { ...valid, identifier: "https://api.internal/?query=1" },
      { ...valid, identifier: "https://user:password@api.internal" },
      { ...valid, name: " " },
      { ...valid, scopes: [] },
      { ...valid, scopes: ["read write"] },
      { ...valid, scopes: ["openid"] },
      { ...valid, scopes: [42] },
    ]) {
      expect((await request("/admin/resources", input)).status, JSON.stringify(input)).toBe(400);
    }
    expect((await request("/admin/resources", valid, { anonymous: true })).status).toBe(401);
    expect(
      (await request("/admin/resources", valid, { origin: "https://evil.example" })).status,
    ).toBe(403);
    expect((await listing()).resources).toEqual([]);
    const context = await service.auth.$context;
    await context.adapter.update({
      model: "session",
      where: [{ field: "userId", value: service.owner()! }],
      update: { createdAt: new Date(Date.now() - 16 * 60_000) },
    });
    expect((await request("/admin/resources", valid)).status).toBe(403);
    expect((await listing()).resources).toEqual([]);
  });

  test("one client accesses multiple resources but each token request targets one", async () => {
    const app = await client();
    expect((await access(app.client_id, [resourceA, resourceB])).status).toBe(200);
    const rows = (await listing()).clientAccess;
    expect(rows).toEqual(
      expect.arrayContaining([
        { client_id: app.client_id, resource: resourceA },
        { client_id: app.client_id, resource: resourceB },
      ]),
    );
    expect((await tokens(app.client_id, resourceA)).access_token).toBeTypeOf("string");
    expect((await tokens(app.client_id, resourceB)).access_token).toBeTypeOf("string");
    expect((await request("/admin/resources/delete", { identifier: resourceA })).status).toBe(409);
    expect((await access(app.client_id, [resourceA, "https://missing.internal/api"])).status).toBe(
      400,
    );
    expect((await listing()).clientAccess).toEqual(rows);
    expect((await access(app.client_id, [])).status).toBe(200);
    expect((await listing()).clientAccess).toEqual([]);
    expect((await request("/admin/resources/delete", { identifier: resourceA })).status).toBe(200);
  });

  test("the same scope label has independent consent on each resource", async () => {
    const app = await client();
    expect((await updateResource(resourceB, ["okf:read", "okf:write"])).status).toBe(200);
    expect((await access(app.client_id, [resourceA, resourceB])).status).toBe(200);
    await authorize(app.client_id, resourceA);
    const flowB = authorization(app.client_id, resourceB, { prompt: "" });
    const authorizationB = new URL(flowB.path, settings.baseURL);
    authorizationB.searchParams.delete("prompt");
    const responseB = await request(`${authorizationB.pathname}${authorizationB.search}`);
    const consentB = new URL(responseB.headers.get("location")!, settings.baseURL);
    expect(consentB.pathname).toBe("/consent");
    expect(
      (
        await request("/api/auth/oauth2/consent", {
          accept: true,
          oauth_query: consentB.search.slice(1),
        })
      ).status,
    ).toBe(200);
    const consents = service.db
      .prepare(
        "SELECT referenceId, resources FROM oauthConsent WHERE clientId = ? ORDER BY referenceId",
      )
      .all(app.client_id);
    expect(consents).toEqual(
      [
        { referenceId: `resource:${resourceA}`, resources: JSON.stringify([resourceA]) },
        { referenceId: `resource:${resourceB}`, resources: JSON.stringify([resourceB]) },
      ].sort((a, b) => a.referenceId.localeCompare(b.referenceId)),
    );
    for (const resource of [resourceA, resourceB]) {
      const prior = await request(authorization(app.client_id, resource, { prompt: "none" }).path);
      const redirect = new URL(prior.headers.get("location")!, settings.baseURL);
      expect(redirect.searchParams.has("code")).toBe(true);
      expect(redirect.searchParams.has("error")).toBe(false);
    }
  });

  test("new scopes appear immediately and need consent; name-only changes preserve refresh grants", async () => {
    const app = await client();
    const issued = await tokens(app.client_id);
    expect((await updateResource(resourceA, ["okf:read", "okf:write"], "Renamed")).status).toBe(
      200,
    );
    expect((await refresh(app.client_id, issued.refresh_token, resourceA)).status).toBe(200);
    expect((await updateResource(resourceA, ["okf:read", "okf:write", "okf:admin"])).status).toBe(
      200,
    );
    const metadata = await (
      await request("/.well-known/oauth-authorization-server/api/auth")
    ).json();
    expect(metadata.scopes_supported).toContain("okf:admin");
    const stored = (await listing()).clients.find(
      (row: { client_id: string }) => row.client_id === app.client_id,
    );
    expect(stored.scope.split(" ")).toContain("okf:admin");
    const response = await request(
      authorization(app.client_id, resourceA, { scope: "openid okf:admin", prompt: "none" }).path,
    );
    expect(
      new URL(response.headers.get("location")!, settings.baseURL).searchParams.get("error"),
    ).toBe("consent_required");
  });

  test("scope removal retires affected grants and codes while another resource survives", async () => {
    const app = await client();
    expect((await access(app.client_id, [resourceA, resourceB])).status).toBe(200);
    expect((await updateResource(resourceB, ["okf:read", "okf:write"])).status).toBe(200);
    const sharedScopes = "openid offline_access okf:read";
    const issuedA = await tokens(app.client_id, resourceA);
    const issuedB = await tokens(app.client_id, resourceB, undefined, sharedScopes);
    const pendingA = await authorize(app.client_id, resourceA);
    const pendingB = await authorize(app.client_id, resourceB, sharedScopes);
    expect((await updateResource(resourceA, ["okf:write"])).status).toBe(200);
    expect((await refresh(app.client_id, issuedA.refresh_token, resourceA)).status).toBe(400);
    expect((await exchange(app.client_id, pendingA, resourceA)).status).toBe(400);
    expect((await refresh(app.client_id, issuedB.refresh_token, resourceB)).status).toBe(200);
    expect((await exchange(app.client_id, pendingB, resourceB)).status).toBe(200);
    expect((await updateResource(resourceA, ["okf:read", "okf:write"])).status).toBe(200);
    expect((await refresh(app.client_id, issuedA.refresh_token, resourceA)).status).toBe(400);
    expect((await exchange(app.client_id, pendingA, resourceA)).status).toBe(400);
  });

  test("unlink and re-add cannot revive old grants or consent and preserve other resource access", async () => {
    const app = await client();
    expect((await access(app.client_id, [resourceA, resourceB])).status).toBe(200);
    const issuedA = await tokens(app.client_id, resourceA);
    const issuedB = await tokens(app.client_id, resourceB);
    const pendingA = await authorize(app.client_id, resourceA);
    expect((await access(app.client_id, [resourceB])).status).toBe(200);
    expect((await access(app.client_id, [resourceA, resourceB])).status).toBe(200);
    expect((await refresh(app.client_id, issuedA.refresh_token, resourceA)).status).toBe(400);
    expect((await exchange(app.client_id, pendingA, resourceA)).status).toBe(400);
    expect((await refresh(app.client_id, issuedB.refresh_token, resourceB)).status).toBe(200);
    const again = await request(authorization(app.client_id, resourceA, { prompt: "none" }).path);
    expect(
      new URL(again.headers.get("location")!, settings.baseURL).searchParams.get("error"),
    ).toBe("consent_required");
    const unaffected = await request(
      authorization(app.client_id, resourceB, {
        scope: "openid offline_access reports:read",
        prompt: "none",
      }).path,
    );
    expect(
      new URL(unaffected.headers.get("location")!, settings.baseURL).searchParams.has("code"),
    ).toBe(true);
  });

  test("a failed scope write rolls back resource policy, client scopes and live discovery", async () => {
    const app = await client();
    const before = await listing();
    const metadataBefore = await (
      await request("/.well-known/oauth-authorization-server/api/auth")
    ).json();
    service.db.exec(
      "CREATE TRIGGER reject_scope_update BEFORE UPDATE OF scopes ON oauthClient BEGIN SELECT RAISE(ABORT, 'injected scope failure'); END",
    );
    try {
      expect((await updateResource(resourceA, ["okf:read", "new:scope"])).status).toBe(500);
      expect(await listing()).toEqual(before);
      const metadataAfter = await (
        await request("/.well-known/oauth-authorization-server/api/auth")
      ).json();
      expect(metadataAfter.scopes_supported).toEqual(metadataBefore.scopes_supported);
    } finally {
      service.db.exec("DROP TRIGGER reject_scope_update");
    }
    expect((await tokens(app.client_id)).access_token).toBeTypeOf("string");
  });

  test("concurrent linking and deletion cannot leave access to a deleted resource", async () => {
    const app = await client();
    const results = await Promise.all([
      access(app.client_id, [resourceA, resourceB]),
      request("/admin/resources/delete", { identifier: resourceB }),
    ]);
    expect(results.map((response) => response.status)).toEqual([200, 409]);
    const state = await listing();
    for (const link of state.clientAccess) {
      expect(
        state.resources.some(
          (resource: { identifier: string }) => resource.identifier === link.resource,
        ),
      ).toBe(true);
    }
  });
});
