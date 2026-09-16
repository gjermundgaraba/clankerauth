import { afterEach, beforeEach, expect, test, vi } from "vite-plus/test";
import { mcpRequest } from "@gjermundgaraba/effect-actions/testing";
import { withMcpClient } from "@gjermundgaraba/effect-actions/testing/client";
import { administrationResource, mcpOAuthGrant } from "./mcp-oauth-helper.ts";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect } from "effect";
import { Actions, Administration } from "@clankerauth/api";
import { createNodeServer, nodeListener } from "../src/node-http.ts";
import { application } from "../src/app.ts";
import { initialize, openAuth, createOwner, type Service } from "../src/auth.ts";
import { validateSettings } from "../src/config.ts";

const origin = "http://localhost:3000";
const resource = "https://example.internal/api";
let directory: string;
let service: Service;
let handle: ReturnType<typeof application>;
let cookie: string;
let bearer: string | undefined;
const call = (path: string, body?: unknown, headers: Record<string, string> = {}) =>
  handle(
    new Request(`${origin}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { origin, cookie, "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
const verify = (key: string, target = resource) =>
  call("/api/verifyApiKey", { resource: target }, { authorization: `Bearer ${key}`, cookie: "" });
beforeEach(async () => {
  bearer = undefined;
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
      await call("/api/createResource", {
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
  const response = await call("/api/createApiKey", {
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
  const list = await call("/api/listApiKeys", {});
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
  expect((await call("/api/updateApiKey", { keyId: key.keyId, enabled: false })).status).toBe(200);
  expect((await verify(key.key)).status).toBe(401);
  expect((await call("/api/updateApiKey", { keyId: key.keyId, enabled: true })).status).toBe(200);
  expect((await verify(key.key)).status).toBe(200);
  expect((await call("/api/deleteApiKey", { keyId: key.keyId })).status).toBe(200);
  expect((await verify(key.key)).status).toBe(401);
});

test("valid-session and Origin administration; keys cannot create sessions or reach plugin routes", async () => {
  const key = await create();
  expect(
    (await call("/api/listApiKeys", {}, { cookie: "", authorization: `Bearer ${key.key}` })).status,
  ).toBe(401);
  expect((await call("/api/listApiKeys", {}, { cookie: "", "x-api-key": key.key })).status).toBe(
    401,
  );
  expect(
    (
      await call(
        "/api/updateApiKey",
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
  await call("/api/updateResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:write"],
  });
  expect((await verify(key.key)).status).toBe(403);
  await call("/api/updateResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write", "example:new"],
  });
  expect((await (await verify(key.key)).json()).scopes).toEqual(["example:read"]);
  await call("/api/deleteResource", { identifier: resource });
  expect((await verify(key.key)).status).toBe(403);
  await call("/api/createResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write"],
  });
  expect((await verify(key.key)).status).toBe(200);
  await call("/api/updateApiKey", {
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
      (await call("/api/createApiKey", { name: "Bad", permissions, expiresAt: null })).status,
    ).toBe(400);
  expect(
    (
      await call("/api/createApiKey", {
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
  const response = await call("/api/listApiKeys", {});
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
    expect((await call("/api/updateApiKey", { keyId: key.keyId, name: "Renamed" })).status).toBe(
      200,
    );
    expect(sessions).toHaveBeenCalledTimes(1);
    expect(
      (await call("/api/updateApiKey", { keyId: key.keyId, enabled: false }, { cookie: "" }))
        .status,
    ).toBe(401);
    expect(
      (
        await call(
          "/api/createApiKey",
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

const mcp = async (
  method: string,
  params: Record<string, unknown> = {},
  headers: Record<string, string> = {},
) => {
  bearer ??= (await mcpOAuthGrant(handle, origin, cookie)).tokens.access_token;
  return handle(
    mcpRequest(method, params, {
      url: `${origin}/mcp`,
      headers: { authorization: `Bearer ${bearer}`, ...headers },
    }),
  );
};

test("HTTP and MCP share administration contracts, writes, secrets and revocation", async () => {
  const discovery = await mcp("tools/list");
  expect(discovery.status).toBe(200);
  expect(discovery.headers.get("cache-control")).toBe("no-store");
  const {
    result: { tools },
  } = await discovery.json();
  expect(tools.map((tool: { name: string }) => tool.name).sort()).toEqual(
    Administration.actions.map((action) => action.name).sort(),
  );
  expect(tools).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        name: "listApiKeys",
        annotations: expect.objectContaining({ readOnlyHint: true }),
      }),
      expect.objectContaining({
        name: "deleteApiKey",
        annotations: expect.objectContaining({ destructiveHint: true }),
      }),
    ]),
  );
  const openapi = await handle(new Request(`${origin}/openapi.json`, { headers: { cookie } }));
  expect(openapi.status).toBe(200);
  const document = await openapi.json();
  expect(Object.keys(document.paths).sort()).toEqual(
    Actions.actions.map((action) => `/api/${action.name}`).sort(),
  );
  for (const name of ["setupStatus", "setupOwner", "verifyApiKey"]) {
    expect(tools).not.toEqual(expect.arrayContaining([expect.objectContaining({ name })]));
  }
  expect(document.paths["/api/createApiKey"].post.responses).toHaveProperty("201");

  const created = await mcp("tools/call", {
    name: "createApiKey",
    arguments: {
      name: "MCP automation",
      permissions: { [resource]: ["example:read"] },
      expiresAt: null,
    },
  });
  expect(created.status).toBe(200);
  const { result } = await created.json();
  expect(result.isError).toBe(false);
  const key = result.structuredContent.value;
  expect(key.key).toMatch(/^ca_/);
  expect((await verify(key.key)).status).toBe(200);
  const listing = await call("/api/listApiKeys", {});
  expect(await listing.json()).toMatchObject({
    keys: [{ keyId: key.keyId, name: "MCP automation" }],
  });
  const mcpListing = await mcp("tools/call", { name: "listApiKeys", arguments: {} });
  expect(await mcpListing.text()).not.toContain(key.key);

  expect((await call("/api/updateApiKey", { keyId: key.keyId, name: "HTTP rename" })).status).toBe(
    200,
  );
  const renamed = await (await mcp("tools/call", { name: "listApiKeys", arguments: {} })).json();
  expect(renamed.result.structuredContent.value.keys[0].name).toBe("HTTP rename");
  const disabled = await (
    await mcp("tools/call", {
      name: "updateApiKey",
      arguments: { keyId: key.keyId, enabled: false },
    })
  ).json();
  expect(disabled.result.structuredContent.value.enabled).toBe(false);
  expect((await verify(key.key)).status).toBe(401);

  const invalid = await (
    await mcp("tools/call", {
      name: "createResource",
      arguments: {
        identifier: "not a URL",
        name: "Invalid",
        scopes: [],
      },
    })
  ).json();
  expect(invalid.result.isError).toBe(true);
  expect(invalid.result.structuredContent._tag).toBe("BadRequest");
  const malformed = await (
    await mcp("tools/call", { name: "updateApiKey", arguments: { keyId: 42 } })
  ).json();
  expect(malformed.result.isError).toBe(true);
  expect(malformed.result.structuredContent).toEqual({
    _tag: "BadRequest",
    error: "Invalid request",
  });
  const malformedHttp = await call("/api/updateApiKey", { keyId: 42 });
  expect(malformedHttp.status).toBe(400);
  expect(await malformedHttp.json()).toEqual(malformed.result.structuredContent);
});

test("HTTP and MCP sanitize invalid managed-client output", async () => {
  const created = await call("/api/createClient", {
    name: "Corrupt-output test",
    redirect: "http://127.0.0.1:9876/callback",
    resources: [],
    native: true,
    confidential: true,
  });
  expect(created.status).toBe(201);
  const { client_id } = await created.json();
  await Effect.runPromise(
    service.sql`UPDATE oauthClient SET redirectUris = ${JSON.stringify([42])} WHERE clientId = ${client_id}`,
  );

  const listing = await call("/api/listClients", {});
  expect(listing.status).toBe(500);
  const expected = { _tag: "InternalServerError", error: "Request could not be completed" };
  expect(await listing.json()).toEqual(expected);

  const tool = await mcp("tools/call", { name: "listClients", arguments: {} });
  expect(tool.status).toBe(200);
  const { result } = await tool.json();
  expect(result.isError).toBe(true);
  expect(result.structuredContent).toEqual(expected);
});

test("HTTP administration requires owner session and Origin; MCP requires bearer authorization", async () => {
  const spoofedOwner = { userId: await Effect.runPromise(service.owner()), cookie };
  expect((await call("/api/listClients", spoofedOwner, { cookie: "" })).status).toBe(401);
  expect(
    (
      await mcp(
        "tools/call",
        { name: "listClients", arguments: spoofedOwner },
        { authorization: "" },
      )
    ).status,
  ).toBe(401);
  const rejectedHeaders: Array<Record<string, string>> = [
    { cookie: "" },
    { origin: "https://evil.example" },
    { origin: "" },
  ];
  for (const headers of rejectedHeaders) {
    const status = headers.cookie === "" ? 401 : 403;
    if (headers.origin !== "") {
      expect((await mcp("tools/list", {}, headers)).status).toBe(headers.cookie === "" ? 200 : 403);
    }
    expect((await call("/api/listClients", {}, headers)).status).toBe(status);
    expect(
      (
        await handle(
          new Request(`${origin}/openapi.json`, { headers: { origin, cookie, ...headers } }),
        )
      ).status,
    ).toBe(headers.cookie === "" ? 401 : 200);
  }
  const key = await create();
  expect(
    (await mcp("tools/list", {}, { cookie: "", authorization: `Bearer ${key.key}` })).status,
  ).toBe(401);
  expect((await call("/api/listClients")).status).toBe(404);
});

test.each(["modern", "legacy"] as const)(
  "official %s MCP client uses OAuth bearer authentication through the Node bridge",
  async (mode) => {
    const { tokens } = await mcpOAuthGrant(handle, origin, cookie);
    const server = createNodeServer(nodeListener(handle, origin));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Expected TCP listener");
      await withMcpClient(
        (request) => fetch(request),
        async (client) => {
          const { tools } = await client.listTools();
          expect(tools.map((tool) => tool.name).sort()).toEqual(
            Administration.actions.map((action) => action.name).sort(),
          );
          const listing = await client.callTool({ name: "listClients", arguments: {} });
          expect(listing.isError).toBe(false);
          expect(listing.structuredContent).toMatchObject({
            value: {
              email: "owner@example.internal",
              resources: [
                administrationResource(origin),
                {
                  identifier: resource,
                  name: "Example",
                  scopes: ["example:read", "example:write"],
                  builtIn: false,
                },
              ],
            },
          });
          const malformed = await client.callTool({
            name: "updateApiKey",
            arguments: { keyId: 42 },
          });
          expect(malformed.isError).toBe(true);
          expect(malformed.structuredContent).toEqual({
            _tag: "BadRequest",
            error: "Invalid request",
          });
        },
        {
          mode,
          path: "/mcp",
          baseUrl: `http://127.0.0.1:${address.port}`,
          headers: { authorization: `Bearer ${tokens.access_token}` },
        },
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  },
);

test("API keys reject administration grants on creation and update without changing stored permissions", async () => {
  const permissions = { [`${origin}/mcp`]: ["admin"] };
  const created = await call("/api/createApiKey", {
    name: "Invalid administration key",
    permissions,
    expiresAt: null,
  });
  expect(created.status).toBe(400);
  const key = await create();
  expect((await call("/api/updateApiKey", { keyId: key.keyId, permissions })).status).toBe(400);
  expect((await (await verify(key.key)).json()).scopes).toEqual(["example:read"]);
});

test("renaming a key preserves grants for resources that are no longer available", async () => {
  const key = await create();
  expect((await call("/api/deleteResource", { identifier: resource })).status).toBe(200);
  expect((await call("/api/updateApiKey", { keyId: key.keyId, name: "Renamed" })).status).toBe(200);
  const { keys } = await (await call("/api/listApiKeys", {})).json();
  expect(keys[0]).toMatchObject({
    name: "Renamed",
    permissions: { [resource]: ["example:read"] },
  });
});
