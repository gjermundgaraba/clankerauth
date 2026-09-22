import { nodeHandler } from "../src/app.ts";
import { afterEach, beforeEach, expect, test, vi } from "vite-plus/test";
import { mcpRequest, type McpRequestParams } from "@gjermundgaraba/effect-actions/Testing";
import { withMcpClient } from "@gjermundgaraba/effect-actions/TestingClient";
import { administrationResource, mcpOAuthGrant } from "./mcp-oauth-helper.ts";
import { Effect, Exit, Scope, Schema } from "effect";
import {
  Administration,
  BadRequest,
  InternalServerError,
  IssuerActions,
} from "@clankerauth/admin-api";
import { createNodeServer } from "../src/node-http.ts";
import { webApplication as application } from "./web-application.ts";
import { createOwner } from "../src/auth.ts";
import { openIssuer, type Issuer } from "./issuer.ts";

const origin = "http://localhost:3000";

const resource = "https://example.internal/api";

const ListenAddress = Schema.Struct({ port: Schema.Number });

const CreatedApiKey = Schema.Struct({ key: Schema.String, keyId: Schema.String });

type JsonPrimitive = string | number | boolean | null;

type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };

type TestRequestBody = { readonly [key: string]: JsonValue };

let issuer: Issuer;

let handle: ReturnType<typeof application>;

let cookie: string;

let bearer: string | undefined;

const call = (path: string, body?: TestRequestBody, headers: Record<string, string> = {}) =>
  handle(
    new Request(`${origin}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { origin, cookie, "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );

const verify = (key: string, target = resource) =>
  call(
    "/api/issuer/verifyApiKey",
    { resource: target },
    { authorization: `Bearer ${key}`, cookie: "" },
  );

beforeEach(async () => {
  bearer = undefined;
  issuer = await openIssuer({ baseURL: origin });
  handle = application(issuer.service);
  await issuer.run(
    createOwner(issuer.service, {
      email: "owner@example.internal",
      password: "test-only password123",
    }),
  );

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
      await call("/api/administration/createResource", {
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
  await issuer.close();
});

const create = async () => {
  const response = await call("/api/administration/createApiKey", {
    name: "Automation",
    permissions: { [resource]: ["example:read"] },
    expiresAt: null,
  });

  expect(response.status).toBe(201);

  return Schema.decodeUnknownSync(CreatedApiKey)(await response.json());
};

test("hash-only storage, explicit scopes, one-time display and next-request disable/delete", async () => {
  const key = await create();
  expect(key.key.startsWith("ca_")).toBe(true);

  const stored = await Effect.runPromise(
    issuer.service
      .sql`SELECT key, rateLimitMax, rateLimitTimeWindow FROM apikey WHERE id = ${key.keyId}`,
  );

  expect(stored[0]?.key).not.toBe(key.key);
  expect(stored[0]?.rateLimitMax).toBe(1000);
  expect(stored[0]?.rateLimitTimeWindow).toBe(60000);
  const list = await call("/api/administration/listApiKeys", {});
  expect(await list.text()).not.toContain(key.key);
  const response = await verify(key.key);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({
    keyId: key.keyId,
    ownerId: await Effect.runPromise(issuer.service.owner()),
    resource,
    scopes: ["example:read"],
    expiresAt: null,
  });
  expect((await verify(key.key, "https://other.internal/api")).status).toBe(403);
  expect(
    (await call("/api/administration/updateApiKey", { keyId: key.keyId, enabled: false })).status,
  ).toBe(200);
  expect((await verify(key.key)).status).toBe(401);
  expect(
    (await call("/api/administration/updateApiKey", { keyId: key.keyId, enabled: true })).status,
  ).toBe(200);
  expect((await verify(key.key)).status).toBe(200);
  expect((await call("/api/administration/deleteApiKey", { keyId: key.keyId })).status).toBe(200);
  expect((await verify(key.key)).status).toBe(401);
});

test("keys cannot authenticate administration, create sessions or reach plugin routes", async () => {
  const key = await create();
  expect(
    (
      await call(
        "/api/administration/listApiKeys",
        {},
        { cookie: "", authorization: `Bearer ${key.key}` },
      )
    ).status,
  ).toBe(401);
  expect(
    (await call("/api/administration/listApiKeys", {}, { cookie: "", "x-api-key": key.key }))
      .status,
  ).toBe(401);
  expect((await call("/api/auth/api-key/create", { name: "Forbidden" })).status).toBe(404);
  expect((await verify("ca_invalid")).status).toBe(401);
});

test("resource policy removal and restoration retains only explicit grants", async () => {
  const key = await create();
  await call("/api/administration/updateResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:write"],
  });
  expect((await verify(key.key)).status).toBe(403);
  await call("/api/administration/updateResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write", "example:new"],
  });
  expect((await (await verify(key.key)).json()).scopes).toEqual(["example:read"]);
  await call("/api/administration/deleteResource", { identifier: resource });
  expect((await verify(key.key)).status).toBe(403);
  await call("/api/administration/createResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write"],
  });
  expect((await verify(key.key)).status).toBe(200);
  await call("/api/administration/updateApiKey", {
    keyId: key.keyId,
    permissions: { [resource]: ["example:write"] },
  });
  expect((await (await verify(key.key)).json()).scopes).toEqual(["example:write"]);
});

test("expired keys and per-key rate limits are enforced", async () => {
  const key = await create();
  await issuer.service.auth.api.updateApiKey({
    body: {
      keyId: key.keyId,
      rateLimitMax: 1,
      userId: await Effect.runPromise(issuer.service.owner()),
    },
  });
  expect((await verify(key.key)).status).toBe(200);
  expect((await verify(key.key)).status).toBe(429);
  await Effect.runPromise(
    issuer.service.sql`UPDATE apikey SET expiresAt = ${Date.now() - 1000} WHERE id = ${key.keyId}`,
  );
  expect((await verify(key.key)).status).toBe(401);
});

test("creation rejects implicit, unknown and invalid expiry grants", async () => {
  const rejected: TestRequestBody[] = [
    { name: "Bad", permissions: {}, expiresAt: null },
    { name: "Bad", permissions: { [resource]: [] }, expiresAt: null },
    { name: "Bad", permissions: { [resource]: ["example:unknown"] }, expiresAt: null },
    { name: "Bad", permissions: { "https://unknown.internal": ["example:read"] }, expiresAt: null },
    { name: "Bad", permissions: { [resource]: ["example:read"] }, expiresAt: "not a date" },
    // The past is a domain refusal, not a malformed request; both are 400.
    {
      name: "Bad",
      permissions: { [resource]: ["example:read"] },
      expiresAt: "2020-01-01T00:00:00.000Z",
    },
  ];

  for (const body of rejected)
    expect((await call("/api/administration/createApiKey", body)).status).toBe(400);
});

test("expiry travels as an ISO timestamp all the way to key verification", async () => {
  const sent = Date.now();
  const requested = sent + 86_400_000;

  const response = await call("/api/administration/createApiKey", {
    name: "Expiring",
    permissions: { [resource]: ["example:read"] },
    expiresAt: new Date(requested).toISOString(),
  });

  expect(response.status).toBe(201);
  const created = await response.json();
  // The plugin takes a lifetime in seconds and dates it itself, so the stored instant
  // is the requested one shifted forward by however far apart those two clock reads
  // are — at most this request's own duration, less the millisecond seconds round away.
  expect(Date.parse(created.expiresAt)).toBeGreaterThanOrEqual(requested - 1);
  expect(Date.parse(created.expiresAt)).toBeLessThanOrEqual(requested + (Date.now() - sent));
  expect(Date.parse(created.createdAt)).toBeLessThanOrEqual(Date.now());
  const expiresAt: string = created.expiresAt;
  const listed = await (await call("/api/administration/listApiKeys", {})).json();
  expect(listed.keys).toEqual([expect.objectContaining({ keyId: created.keyId, expiresAt })]);
  expect(await (await verify(created.key)).json()).toMatchObject({ expiresAt });
});

test("listing returns key metadata without plaintext", async () => {
  const created = [];

  for (let index = 0; index < 5; index++) created.push(await create());
  const response = await call("/api/administration/listApiKeys", {});
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(body.keys).toHaveLength(created.length);
  expect(new Set(body.keys.map((key: { keyId: string }) => key.keyId))).toEqual(
    new Set(created.map((key) => key.keyId)),
  );

  for (const key of created) expect(JSON.stringify(body)).not.toContain(key.key);
});

test("key writes require owner authorization", async () => {
  const key = await create();
  expect(
    (await call("/api/administration/updateApiKey", { keyId: key.keyId, name: "Renamed" })).status,
  ).toBe(200);
  expect(
    (
      await call(
        "/api/administration/updateApiKey",
        { keyId: key.keyId, enabled: false },
        { cookie: "" },
      )
    ).status,
  ).toBe(401);
});

const mcp = async (
  method: string,
  params: McpRequestParams = {},
  headers: Record<string, string> = {},
) => {
  bearer ??= (await mcpOAuthGrant(handle, origin, cookie)).tokens.access_token;

  return handle(
    mcpRequest({
      method,
      params,
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

  const openapi = await handle(new Request(`${origin}/openapi.json`));
  expect(openapi.status).toBe(200);
  const document = await openapi.json();
  expect(Object.keys(document.paths).sort()).toEqual(
    [Administration, IssuerActions]
      .flatMap((group) => group.actions.map((action) => `/api/${group.name}/${action.name}`))
      .sort(),
  );

  for (const name of ["setupStatus", "setupOwner", "verifyApiKey"]) {
    expect(tools).not.toEqual(expect.arrayContaining([expect.objectContaining({ name })]));
  }

  expect(document.paths["/api/administration/createApiKey"].post.responses).toHaveProperty("201");

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
  const listing = await call("/api/administration/listApiKeys", {});
  expect(await listing.json()).toMatchObject({
    keys: [{ keyId: key.keyId, name: "MCP automation" }],
  });
  const mcpListing = await mcp("tools/call", { name: "listApiKeys", arguments: {} });
  expect(await mcpListing.text()).not.toContain(key.key);

  expect(
    (
      await call("/api/administration/updateApiKey", {
        keyId: key.keyId,
        name: "HTTP rename",
      })
    ).status,
  ).toBe(200);
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
  expect(invalid.result.structuredContent).toBeUndefined();
  expect(JSON.parse(invalid.result.content[0].text)._tag).toBe("BadRequest");

  const malformed = await (
    await mcp("tools/call", { name: "updateApiKey", arguments: { keyId: 42 } })
  ).json();

  expect(malformed.result.isError).toBe(true);
  expect(malformed.result.structuredContent).toBeUndefined();
  expect(malformed.result.content[0].text).toContain("Invalid parameters for tool 'updateApiKey'");
  const malformedHttp = await call("/api/administration/updateApiKey", { keyId: 42 });
  expect(malformedHttp.status).toBe(400);
  expect(await malformedHttp.json()).toEqual(
    Schema.encodeSync(BadRequest)(new BadRequest({ error: "Invalid request" })),
  );
});

test("HTTP and MCP sanitize invalid managed-client output", async () => {
  const created = await call("/api/administration/createClient", {
    client_name: "Corrupt-output test",
    redirect_uris: ["http://127.0.0.1:9876/callback"],
    resources: [],
    application_type: "native",
    token_endpoint_auth_method: "client_secret_basic",
  });

  expect(created.status).toBe(201);
  const { client_id } = await created.json();
  await Effect.runPromise(
    issuer.service
      .sql`UPDATE oauthClient SET redirectUris = ${JSON.stringify([42])} WHERE clientId = ${client_id}`,
  );

  const listing = await call("/api/administration/listClients", {});
  expect(listing.status).toBe(500);

  const expected = Schema.encodeSync(InternalServerError)(
    new InternalServerError({ error: "Request could not be completed" }),
  );

  expect(await listing.json()).toEqual(expected);

  const tool = await mcp("tools/call", { name: "listClients", arguments: {} });
  expect(tool.status).toBe(200);
  const { result } = await tool.json();
  expect(result.isError).toBe(true);
  expect(result.structuredContent).toBeUndefined();
  expect(JSON.parse(result.content[0].text)).toEqual(expected);
});

test("HTTP administration requires the owner session; MCP requires bearer authorization", async () => {
  const userId = await Effect.runPromise(issuer.service.owner());

  if (userId === undefined) throw new Error("Expected an owner for spoofed-session checks");
  const spoofedOwner = { userId, cookie };
  expect((await call("/api/administration/listClients", spoofedOwner, { cookie: "" })).status).toBe(
    401,
  );
  expect(
    (
      await mcp(
        "tools/call",
        { name: "listClients", arguments: spoofedOwner },
        { authorization: "" },
      )
    ).status,
  ).toBe(401);

  expect((await call("/api/administration/listClients", {}, { cookie: "" })).status).toBe(401);
  expect((await mcp("tools/list", {}, { cookie: "" })).status).toBe(200);

  // The SameSite session cookie is the CSRF boundary; owner actions do not inspect Origin.
  for (const origin of ["https://evil.example", ""])
    expect((await call("/api/administration/listClients", {}, { origin })).status).toBe(200);
  // MCP validates Origin as the protocol requires.
  expect((await mcp("tools/list", {}, { origin: "https://evil.example" })).status).toBe(403);

  const key = await create();
  expect(
    (await mcp("tools/list", {}, { cookie: "", authorization: `Bearer ${key.key}` })).status,
  ).toBe(401);
  expect((await call("/api/administration/listClients")).status).toBe(404);
});

test.each(["2026-07-28", "2025-11-25"] as const)(
  "official %s MCP client uses OAuth bearer authentication through native Effect HTTP",
  async (protocolVersion) => {
    const { tokens } = await mcpOAuthGrant(handle, origin, cookie);
    const scope = Scope.makeUnsafe();

    const listener = await issuer.run(
      nodeHandler().pipe(Effect.provideService(Scope.Scope, scope)),
    );

    const server = createNodeServer(listener);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));

    try {
      const { port } = Schema.decodeUnknownSync(ListenAddress)(server.address());
      await withMcpClient(
        {
          fetch: (request) => fetch(request),
          versionNegotiation:
            protocolVersion === "2026-07-28"
              ? { mode: { pin: protocolVersion } }
              : { mode: "legacy" },
          path: "/mcp",
          baseUrl: `http://127.0.0.1:${port}`,
          headers: { authorization: `Bearer ${tokens.access_token}` },
        },
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
          expect(malformed.structuredContent).toBeUndefined();
          expect(malformed.content).toEqual([
            expect.objectContaining({
              type: "text",
              text: expect.stringContaining("Invalid parameters for tool 'updateApiKey'"),
            }),
          ]);
        },
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      await Effect.runPromise(Scope.close(scope, Exit.void));
    }
  },
);

test("API keys reject administration grants on creation and update without changing stored permissions", async () => {
  const permissions = { [`${origin}/mcp`]: ["admin"] };

  const created = await call("/api/administration/createApiKey", {
    name: "Invalid administration key",
    permissions,
    expiresAt: null,
  });

  expect(created.status).toBe(400);
  const key = await create();
  expect(
    (await call("/api/administration/updateApiKey", { keyId: key.keyId, permissions })).status,
  ).toBe(400);
  expect((await (await verify(key.key)).json()).scopes).toEqual(["example:read"]);
});

test("renaming a key preserves grants for resources that are no longer available", async () => {
  const key = await create();
  expect((await call("/api/administration/deleteResource", { identifier: resource })).status).toBe(
    200,
  );
  expect(
    (await call("/api/administration/updateApiKey", { keyId: key.keyId, name: "Renamed" })).status,
  ).toBe(200);
  const { keys } = await (await call("/api/administration/listApiKeys", {})).json();
  expect(keys[0]).toMatchObject({
    name: "Renamed",
    permissions: { [resource]: ["example:read"] },
  });
});
