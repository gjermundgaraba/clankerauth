import { nodeHandler } from "../src/app.ts";
import { afterEach, beforeEach, expect, test, vi } from "vite-plus/test";
import {
  mcpCall,
  mcpRequest,
  type McpCallOptions,
  type McpRequestParams,
} from "@gjermundgaraba/effect-actions/Testing";
import { withMcpClient } from "@gjermundgaraba/effect-actions/TestingClient";
import { administrationResource, mcpOAuthGrant } from "./mcp-oauth-helper.ts";
import { Effect, Exit, Layer, Result, Scope, Schema } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import * as KeyList from "@gjermundgaraba/clankerauth-sdk/key-list";
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

const keyList = (target = resource) =>
  call("/api/issuer/keyList", { resource: target }, { cookie: "" });

/**
 * What a resource server decides for this key once it reads its next key list: the
 * SDK's own verifier, cold, against this issuer in-process.
 */
const verify = async (key: string, target = resource) => {
  const loopback: typeof fetch = (input, init) => handle(new Request(input, init));

  const result = await Effect.runPromise(
    Effect.result(
      Effect.flatMap(
        Verifier.make({ issuer: `${origin}/api/auth`, resource: target }),
        (verifier) => verifier.verifyToken(key),
      ),
    ).pipe(
      Effect.provide(
        FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, loopback))),
      ),
    ),
  );

  return Result.isSuccess(result) ? result.success : result.failure._tag;
};

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

test("hash-only storage, explicit scopes, one-time display and next-list disable/delete", async () => {
  const key = await create();
  expect(key.key.startsWith("clankerauth_")).toBe(true);

  const stored = await Effect.runPromise(
    issuer.service.sql`SELECT key FROM apikey WHERE id = ${key.keyId}`,
  );

  // The digest the provider stores is the one a resource server derives from the key.
  expect(stored[0]?.key).toBe(Buffer.from(await KeyList.digest(key.key)).toString("base64url"));
  const list = await call("/api/administration/listApiKeys", {});
  expect(await list.text()).not.toContain(key.key);
  expect(await verify(key.key)).toEqual({
    subject: await Effect.runPromise(issuer.service.owner()),
    scopes: ["example:read"],
    actor: { kind: "key", keyId: key.keyId },
    expiresAt: undefined,
  });
  expect(await verify(key.key, "https://other.internal/api")).toBe("Unauthorized");
  expect(
    (await call("/api/administration/updateApiKey", { keyId: key.keyId, enabled: false })).status,
  ).toBe(200);
  expect(await verify(key.key)).toBe("Unauthorized");
  expect(
    (await call("/api/administration/updateApiKey", { keyId: key.keyId, enabled: true })).status,
  ).toBe(200);
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
  expect((await call("/api/administration/deleteApiKey", { keyId: key.keyId })).status).toBe(200);
  expect(await verify(key.key)).toBe("Unauthorized");
});

test("a key list is signed for its resource, never cached, and reveals nothing without the key", async () => {
  const key = await create();
  const owner = await Effect.runPromise(issuer.service.owner());
  const response = await keyList();
  expect(response.status).toBe(200);
  expect(response.headers.get("cache-control")).toBe("no-store");
  const { list } = await response.json();
  expect(decodeProtectedHeader(list)).toMatchObject({ alg: "EdDSA", typ: KeyList.type });
  const claims = decodeJwt(list);
  expect(claims).toMatchObject({ iss: `${origin}/api/auth`, aud: resource });
  expect((claims.exp ?? 0) - (claims.iat ?? 0)).toBe(KeyList.lifetime);
  const entries = Schema.decodeUnknownSync(KeyList.Claims)(claims).keys;
  expect(entries).toHaveLength(1);
  // An entry is its lookup ID and a sealed box, nothing readable besides.
  expect(Object.keys(entries[0] ?? {}).sort()).toEqual(["id", "sealed"]);
  const sealed = Buffer.from(entries[0]?.sealed ?? "", "base64url").toString("latin1");

  for (const secret of [key.keyId, owner ?? "", "example:read"])
    expect(sealed).not.toContain(secret);

  // Unknown resources and administration have no entries, and say nothing more.
  await Effect.runPromise(
    issuer.service
      .sql`UPDATE apikey SET permissions = ${JSON.stringify({ [resource]: ["example:read"], [`${origin}/mcp`]: ["clankerauth:write"] })} WHERE id = ${key.keyId}`,
  );

  for (const target of ["https://unknown.internal/api", `${origin}/mcp`]) {
    const empty = await keyList(target);
    expect(empty.status).toBe(200);
    expect(decodeJwt((await empty.json()).list)).toMatchObject({ aud: target, keys: [] });
  }

  expect(await verify(key.key, `${origin}/mcp`)).toBe("Unauthorized");
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
  expect(await verify("clankerauth_invalid")).toBe("Unauthorized");
});

test("one key reaches several resources, each with only its own scopes", async () => {
  const host = "https://host.example.internal/";
  expect(
    (
      await call("/api/administration/createResource", {
        identifier: host,
        name: "Host",
        scopes: ["host:read", "host:write"],
      })
    ).status,
  ).toBe(201);

  const created = await call("/api/administration/createApiKey", {
    name: "Controller",
    permissions: { [resource]: ["example:read"], [host]: ["host:write"] },
    expiresAt: null,
  });

  const key = Schema.decodeUnknownSync(CreatedApiKey)(await created.json());
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
  expect(await verify(key.key, host)).toMatchObject({ scopes: ["host:write"] });

  // A key granted on one resource alone is refused by the other.
  const example = await create();
  expect(await verify(example.key, host)).toBe("Unauthorized");
});

test("resource policy removal and restoration retains only explicit grants", async () => {
  const key = await create();
  await call("/api/administration/updateResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:write"],
  });
  expect(await verify(key.key)).toBe("Unauthorized");
  await call("/api/administration/updateResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write", "example:new"],
  });
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
  await call("/api/administration/deleteResource", { identifier: resource });
  expect(await verify(key.key)).toBe("Unauthorized");
  await call("/api/administration/createResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write"],
  });
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
  await call("/api/administration/updateApiKey", {
    keyId: key.keyId,
    permissions: { [resource]: ["example:write"] },
  });
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:write"] });
});

test("expired keys leave the key list", async () => {
  const key = await create();
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
  expect(decodeJwt((await (await keyList()).json()).list).keys).toHaveLength(1);
  await Effect.runPromise(
    issuer.service
      .sql`UPDATE apikey SET expiresAt = ${new Date(Date.now() - 1000).toISOString()} WHERE id = ${key.keyId}`,
  );
  expect(decodeJwt((await (await keyList()).json()).list).keys).toEqual([]);
  expect(await verify(key.key)).toBe("Unauthorized");
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
  // Sealed in the key's entry, so a resource server enforces it without the issuer.
  expect(await verify(created.key)).toMatchObject({ expiresAt: Date.parse(expiresAt) });
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

const ownerBearer = async () =>
  (bearer ??= (await mcpOAuthGrant(handle, origin, cookie)).tokens.access_token);

const mcp = async (
  method: string,
  params: McpRequestParams = {},
  headers: Record<string, string> = {},
) =>
  handle(
    mcpRequest({
      method,
      params,
      url: `${origin}/mcp`,
      headers: { authorization: `Bearer ${await ownerBearer()}`, ...headers },
    }),
  );

const tool = async (name: string, arguments_: McpCallOptions["arguments"] = {}) =>
  mcpCall(handle, {
    url: `${origin}/mcp`,
    name,
    arguments: arguments_,
    headers: { authorization: `Bearer ${await ownerBearer()}` },
  });

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

  for (const name of ["setupStatus", "setupOwner", "keyList"]) {
    expect(tools).not.toEqual(expect.arrayContaining([expect.objectContaining({ name })]));
  }

  expect(document.paths["/api/administration/createApiKey"].post.responses).toHaveProperty("201");

  const created = await tool("createApiKey", {
    name: "MCP automation",
    permissions: { [resource]: ["example:read"] },
    expiresAt: null,
  });

  expect(created.isError).toBe(false);
  const key = Schema.decodeUnknownSync(Schema.Struct({ value: CreatedApiKey }))(created).value;
  expect(key.key).toMatch(/^clankerauth_/);
  expect(await verify(key.key)).toMatchObject({ actor: { kind: "key", keyId: key.keyId } });
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
  expect(await tool("listApiKeys")).toMatchObject({
    isError: false,
    value: { keys: [{ keyId: key.keyId, name: "HTTP rename" }] },
  });
  expect(await tool("updateApiKey", { keyId: key.keyId, enabled: false })).toMatchObject({
    isError: false,
    value: { keyId: key.keyId, enabled: false },
  });
  expect(await verify(key.key)).toBe("Unauthorized");

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

test("a key with malformed stored permissions grants nothing, stays listed and can be deleted", async () => {
  const key = await create();
  const intact = await create();
  await Effect.runPromise(
    issuer.service
      .sql`UPDATE apikey SET permissions = ${JSON.stringify({ [resource]: [42] })} WHERE id = ${key.keyId}`,
  );

  // The broken key fails closed on its own; every other key verifies as before.
  expect(await verify(key.key)).toBe("Unauthorized");
  expect(await verify(intact.key)).toMatchObject({ actor: { kind: "key", keyId: intact.keyId } });

  const listing = await call("/api/administration/listApiKeys", {});
  expect(listing.status).toBe(200);
  expect((await listing.json()).keys).toEqual([
    expect.objectContaining({ keyId: key.keyId, permissions: {} }),
    expect.objectContaining({ keyId: intact.keyId, permissions: { [resource]: ["example:read"] } }),
  ]);
  expect((await call("/api/administration/deleteApiKey", { keyId: key.keyId })).status).toBe(200);
});

test("a key row that decodes but cannot be sealed is left out on its own", async () => {
  const key = await create();
  const intact = await create();
  await Effect.runPromise(
    issuer.service.sql`UPDATE apikey SET referenceId = '' WHERE id = ${key.keyId}`,
  );

  expect(await verify(key.key)).toBe("Unauthorized");
  expect(await verify(intact.key)).toMatchObject({ actor: { kind: "key", keyId: intact.keyId } });
  await Effect.runPromise(issuer.service.sql`DELETE FROM apikey WHERE id = ${key.keyId}`);
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

test("official 2026-07-28 MCP client uses OAuth bearer authentication through native Effect HTTP", async () => {
  const { tokens } = await mcpOAuthGrant(handle, origin, cookie);
  const scope = Scope.makeUnsafe();

  const listener = await issuer.run(nodeHandler().pipe(Effect.provideService(Scope.Scope, scope)));

  const server = createNodeServer(listener);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));

  try {
    const { port } = Schema.decodeUnknownSync(ListenAddress)(server.address());
    await withMcpClient(
      {
        fetch: (request) => fetch(request),
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
});

test("API keys reject administration grants on creation and update without changing stored permissions", async () => {
  const permissions = { [`${origin}/mcp`]: ["clankerauth:write"] };

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
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
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
