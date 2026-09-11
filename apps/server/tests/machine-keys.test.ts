import { afterEach, beforeEach, expect, test, vi } from "vite-plus/test";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect } from "effect";
import { application } from "../src/app.ts";
import { initialize, openAuth, createOwner, type Service } from "../src/auth.ts";
import { validateSettings } from "../src/config.ts";

const origin = "http://localhost:3000";
const resource = "https://example.internal/api";
let directory: string;
let service: Service;
let handle: ReturnType<typeof application>;
let cookie: string;
const call = (path: string, body?: unknown, headers: Record<string, string> = {}) =>
  handle(
    new Request(`${origin}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { origin, cookie, "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
const verify = (key: string, target = resource) =>
  call(
    "/api/api-keys/verify",
    { resource: target },
    { authorization: `Bearer ${key}`, cookie: "" },
  );
beforeEach(async () => {
  directory = mkdtempSync(join(tmpdir(), "clankerauth-keys-"));
  service = await openAuth(
    validateSettings({
      baseURL: origin,
      secret: randomBytes(32).toString("hex"),
      database: join(directory, "auth.sqlite"),
      host: "127.0.0.1",
      port: 3000,
    }),
  );
  await initialize(service);
  handle = application(service);
  await createOwner(service, {
    email: "owner@example.internal",
    password: "test-only password123",
  });
  const login = await call("/api/auth/sign-in/email", {
    email: "owner@example.internal",
    password: "test-only password123",
  });
  cookie = login.headers
    .getSetCookie()
    .map((part) => part.split(";")[0])
    .join("; ");
  expect(
    (
      await call("/admin/resources", {
        identifier: resource,
        name: "Example",
        scopes: ["example:read", "example:write"],
      })
    ).status,
  ).toBe(201);
});
afterEach(async () => {
  vi.useRealTimers();
  await handle.dispose();
  await service.close();
  rmSync(directory, { recursive: true, force: true });
});
const create = async () => {
  const response = await call("/admin/api-keys", {
    name: "Automation",
    permissions: { [resource]: ["example:read"] },
    expiresAt: null,
  });
  expect(response.status).toBe(201);
  return (await response.json()) as { key: string; keyId: string };
};

test("hash-only storage, explicit scopes, one-time display and next-request disable/delete", async () => {
  const key = await create();
  expect(key.key.startsWith("ca_")).toBe(true);
  const stored = await Effect.runPromise(
    service.sql`SELECT key, rateLimitMax, rateLimitTimeWindow FROM apikey WHERE id = ${key.keyId}`,
  );
  expect(stored[0]?.key).not.toBe(key.key);
  expect(stored[0]?.rateLimitMax).toBe(1000);
  expect(stored[0]?.rateLimitTimeWindow).toBe(60000);
  const list = await call("/admin/api-keys");
  expect(await list.text()).not.toContain(key.key);
  const response = await verify(key.key);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({
    keyId: key.keyId,
    ownerId: await Effect.runPromise(service.owner()),
    resource,
    scopes: ["example:read"],
    expiresAt: null,
  });
  expect((await verify(key.key, "https://other.internal/api")).status).toBe(403);
  expect((await call("/admin/api-keys/update", { keyId: key.keyId, enabled: false })).status).toBe(
    200,
  );
  expect((await verify(key.key)).status).toBe(401);
  expect((await call("/admin/api-keys/update", { keyId: key.keyId, enabled: true })).status).toBe(
    200,
  );
  expect((await verify(key.key)).status).toBe(200);
  expect((await call("/admin/api-keys/delete", { keyId: key.keyId })).status).toBe(200);
  expect((await verify(key.key)).status).toBe(401);
});

test("valid-session and Origin administration; keys cannot create sessions or reach plugin routes", async () => {
  const key = await create();
  expect(
    (await call("/admin/api-keys", undefined, { cookie: "", authorization: `Bearer ${key.key}` }))
      .status,
  ).toBe(401);
  expect(
    (await call("/admin/api-keys", undefined, { cookie: "", "x-api-key": key.key })).status,
  ).toBe(401);
  expect(
    (
      await call(
        "/admin/api-keys/update",
        { keyId: key.keyId, enabled: false },
        { origin: "https://evil.example" },
      )
    ).status,
  ).toBe(403);
  expect((await call("/api/auth/api-key/create", { name: "Forbidden" })).status).toBe(404);
  expect((await verify("ca_invalid")).status).toBe(401);
});

test("resource policy removal and restoration retains only explicit grants", async () => {
  const key = await create();
  await call("/admin/resources/update", {
    identifier: resource,
    name: "Example",
    scopes: ["example:write"],
  });
  expect((await verify(key.key)).status).toBe(403);
  await call("/admin/resources/update", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write", "example:new"],
  });
  expect((await (await verify(key.key)).json()).scopes).toEqual(["example:read"]);
  await call("/admin/resources/delete", { identifier: resource });
  expect((await verify(key.key)).status).toBe(403);
  await call("/admin/resources", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write"],
  });
  expect((await verify(key.key)).status).toBe(200);
  await call("/admin/api-keys/update", {
    keyId: key.keyId,
    permissions: { [resource]: ["example:write"] },
  });
  expect((await (await verify(key.key)).json()).scopes).toEqual(["example:write"]);
});

test("expired keys and per-key rate limits are enforced", async () => {
  const key = await create();
  await service.auth.api.updateApiKey({
    body: { keyId: key.keyId, rateLimitMax: 1, userId: await Effect.runPromise(service.owner()) },
  });
  expect((await verify(key.key)).status).toBe(200);
  expect((await verify(key.key)).status).toBe(429);
  await Effect.runPromise(
    service.sql`UPDATE apikey SET expiresAt = ${Date.now() - 1000} WHERE id = ${key.keyId}`,
  );
  expect((await verify(key.key)).status).toBe(401);
});

test("creation rejects implicit, unknown and invalid expiry grants", async () => {
  for (const permissions of [
    {},
    { [resource]: [] },
    { [resource]: ["example:unknown"] },
    { "https://unknown.internal": ["example:read"] },
  ])
    expect(
      (await call("/admin/api-keys", { name: "Bad", permissions, expiresAt: null })).status,
    ).toBe(400);
  expect(
    (
      await call("/admin/api-keys", {
        name: "Bad",
        permissions: { [resource]: ["example:read"] },
        expiresAt: "not a date",
      })
    ).status,
  ).toBe(400);
});

test("listing includes every key beyond the provider database page and preserves pagination", async () => {
  const created = [];
  for (let index = 0; index < 101; index++) created.push(await create());
  const response = await call("/admin/api-keys");
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(body.keys).toHaveLength(created.length);
  expect(new Set(body.keys.map((key: { keyId: string }) => key.keyId))).toEqual(
    new Set(created.map((key) => key.keyId)),
  );
  for (const key of created) expect(JSON.stringify(body)).not.toContain(key.key);
  const headers = new Headers({ cookie });
  const all = await service.auth.api.listApiKeys({
    headers,
    query: { limit: 1000, sortBy: "id", sortDirection: "asc" },
  });
  expect(all.apiKeys).toHaveLength(101);
  expect(all.total).toBe(101);
  const last = await service.auth.api.listApiKeys({
    headers,
    query: { limit: 1, offset: 100, sortBy: "id", sortDirection: "asc" },
  });
  expect(last.apiKeys.map((key) => key.id)).toEqual([all.apiKeys[100]!.id]);
  expect(last.total).toBe(101);
});

test("key writes reuse middleware owner authorization", async () => {
  const sessions = vi.spyOn(service.auth.api, "getSession");
  try {
    const key = await create();
    expect(sessions).toHaveBeenCalledTimes(1);
    sessions.mockClear();
    expect(
      (await call("/admin/api-keys/update", { keyId: key.keyId, name: "Renamed" })).status,
    ).toBe(200);
    expect(sessions).toHaveBeenCalledTimes(1);
    expect(
      (await call("/admin/api-keys/update", { keyId: key.keyId, enabled: false }, { cookie: "" }))
        .status,
    ).toBe(401);
    expect(
      (
        await call(
          "/admin/api-keys",
          { name: "Denied", permissions: { [resource]: ["example:read"] }, expiresAt: null },
          { origin: "https://evil.example" },
        )
      ).status,
    ).toBe(403);
  } finally {
    sessions.mockRestore();
  }
});

test("sustained verification below the per-minute limit never accumulates across windows", async () => {
  const key = await create();
  const start = Date.now();
  vi.useFakeTimers({ toFake: ["Date"] });
  for (let second = 0; second <= 1200; second++) {
    vi.setSystemTime(start + second * 1000);
    expect((await verify(key.key)).status, `request ${second + 1}`).toBe(200);
  }
  const rows = await Effect.runPromise(
    service.sql`SELECT requestCount, lastRequest, rateLimitWindowStart FROM apikey WHERE id = ${key.keyId}`,
  );
  expect(rows[0]?.requestCount).toBe(1);
  expect(new Date(String(rows[0]?.rateLimitWindowStart)).getTime()).toBe(start + 1200000);
  expect(rows[0]?.lastRequest).toEqual(rows[0]?.rateLimitWindowStart);
});

test("concurrent verification respects fixed-window capacity and resets at the exact boundary", async () => {
  const key = await create();
  await service.auth.api.updateApiKey({
    body: { keyId: key.keyId, rateLimitMax: 3, userId: await Effect.runPromise(service.owner()) },
  });
  const start = Date.now();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(start);
  const burst = async () => {
    const responses = await Promise.all(Array.from({ length: 20 }, () => verify(key.key)));
    expect(responses.filter((response) => response.status === 200)).toHaveLength(3);
    expect(responses.filter((response) => response.status === 429)).toHaveLength(17);
  };
  await burst();
  vi.setSystemTime(start + 59999);
  expect((await verify(key.key)).status).toBe(429);
  vi.setSystemTime(start + 60000);
  await burst();
  const settings = service.settings;
  await handle.dispose();
  await service.close();
  service = await openAuth(settings);
  await initialize(service);
  handle = application(service);
  expect((await verify(key.key)).status).toBe(429);
  vi.setSystemTime(start + 120000);
  expect((await verify(key.key)).status).toBe(200);
});
