import { nodeHandler } from "../src/app.ts";
import { afterEach, beforeEach, expect, test, vi } from "vite-plus/test";
import { administrationTools, webMcpRequest, withMcpClient } from "./mcp.ts";
import { administrationResource, mcpOAuthGrant } from "./mcp-oauth-helper.ts";
import { Effect, Exit, Layer, Result, Scope, Schema } from "effect";
import { FetchHttpClient } from "effect/http";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import type * as Testing from "@gjermundgaraba/effect-actions/Testing";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import * as KeyList from "@gjermundgaraba/clankerauth-sdk/key-list";
import { Administration, InternalServerError } from "@clankerauth/admin-api";
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

const keyList = (target = resource) => call("/api/keyList", { resource: target }, { cookie: "" });

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
  await issuer.close();
});

const create = async () => {
  const response = await call("/api/createApiKey", {
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
  const list = await call("/api/listApiKeys", {});
  expect(await list.text()).not.toContain(key.key);
  expect(await verify(key.key)).toEqual({
    subject: await Effect.runPromise(issuer.service.owner()),
    scopes: ["example:read"],
    actor: { kind: "key", keyId: key.keyId },
    expiresAt: undefined,
  });
  expect(await verify(key.key, "https://other.internal/api")).toBe("Unauthorized");
  expect((await call("/api/updateApiKey", { keyId: key.keyId, enabled: false })).status).toBe(200);
  expect(await verify(key.key)).toBe("Unauthorized");
  expect((await call("/api/updateApiKey", { keyId: key.keyId, enabled: true })).status).toBe(200);
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
  expect((await call("/api/deleteApiKey", { keyId: key.keyId })).status).toBe(200);
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
      .sql`UPDATE apikey SET permissions = ${JSON.stringify({ [resource]: ["example:read"], [`${origin}/`]: ["clankerauth:write"] })} WHERE id = ${key.keyId}`,
  );

  for (const target of ["https://unknown.internal/api", `${origin}/`]) {
    const empty = await keyList(target);
    expect(empty.status).toBe(200);
    expect(decodeJwt((await empty.json()).list)).toMatchObject({ aud: target, keys: [] });
  }

  expect(await verify(key.key, `${origin}/`)).toBe("Unauthorized");
});

test("keys cannot authenticate administration, create sessions or reach plugin routes", async () => {
  const key = await create();
  expect(
    (await call("/api/listApiKeys", {}, { cookie: "", authorization: `Bearer ${key.key}` })).status,
  ).toBe(401);
  expect((await call("/api/listApiKeys", {}, { cookie: "", "x-api-key": key.key })).status).toBe(
    401,
  );
  expect((await call("/api/auth/api-key/create", { name: "Forbidden" })).status).toBe(404);
  expect(await verify("clankerauth_invalid")).toBe("Unauthorized");
});

test("one key reaches several resources, each with only its own scopes", async () => {
  const host = "https://host.example.internal/";
  expect(
    (
      await call("/api/createResource", {
        identifier: host,
        name: "Host",
        scopes: ["host:read", "host:write"],
      })
    ).status,
  ).toBe(201);

  const created = await call("/api/createApiKey", {
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
  await call("/api/updateResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:write"],
  });
  expect(await verify(key.key)).toBe("Unauthorized");
  await call("/api/updateResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write", "example:new"],
  });
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
  await call("/api/deleteResource", { identifier: resource });
  expect(await verify(key.key)).toBe("Unauthorized");
  await call("/api/createResource", {
    identifier: resource,
    name: "Example",
    scopes: ["example:read", "example:write"],
  });
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
  await call("/api/updateApiKey", {
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

test("creation rejects implicit, unknown and invalid expiry grants, naming the field", async () => {
  const unknown = "https://unknown.internal";

  const rejected: ReadonlyArray<readonly [TestRequestBody, ReadonlyArray<string>]> = [
    [{ name: "Bad", permissions: {}, expiresAt: null }, ["permissions"]],
    [{ name: "Bad", permissions: { [resource]: [] }, expiresAt: null }, ["permissions", resource]],
    [
      { name: "Bad", permissions: { [resource]: ["example:unknown"] }, expiresAt: null },
      ["permissions", resource],
    ],
    [
      { name: "Bad", permissions: { [unknown]: ["example:read"] }, expiresAt: null },
      ["permissions", unknown],
    ],
    [{ name: "", permissions: { [resource]: ["example:read"] }, expiresAt: null }, ["name"]],
    // The past decodes but cannot be served: the built-in 400, naming the field.
    [
      {
        name: "Bad",
        permissions: { [resource]: ["example:read"] },
        expiresAt: "2020-01-01T00:00:00.000Z",
      },
      ["expiresAt"],
    ],
  ];

  for (const [body, path] of rejected) {
    const response = await call("/api/createApiKey", body);
    expect(response.status).toBe(400);
    const refused = await response.json();
    expect(refused._tag).toBe("InvalidInput");
    expect(refused.issues.map((issue: { readonly path: unknown }) => issue.path)).toContainEqual(
      path,
    );
  }
});

test("expiry travels as an ISO timestamp all the way to key verification", async () => {
  const sent = Date.now();
  const requested = sent + 86_400_000;

  const response = await call("/api/createApiKey", {
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
  const listed = await (await call("/api/listApiKeys", {})).json();
  expect(listed.keys).toEqual([expect.objectContaining({ keyId: created.keyId, expiresAt })]);
  // Sealed in the key's entry, so a resource server enforces it without the issuer.
  expect(await verify(created.key)).toMatchObject({ expiresAt: Date.parse(expiresAt) });
});

test("listing returns key metadata without plaintext", async () => {
  const created = [];

  for (let index = 0; index < 5; index++) created.push(await create());
  const response = await call("/api/listApiKeys", {});
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
  expect((await call("/api/updateApiKey", { keyId: key.keyId, name: "Renamed" })).status).toBe(200);
  expect(
    (await call("/api/updateApiKey", { keyId: key.keyId, enabled: false }, { cookie: "" })).status,
  ).toBe(401);
});

const ownerBearer = async () =>
  (bearer ??= (await mcpOAuthGrant(handle, origin, cookie)).tokens.access_token);

const mcp = async (
  method: string,
  params: Testing.McpParams = {},
  headers: Record<string, string> = {},
) =>
  handle(
    webMcpRequest({
      method,
      params,
      url: `${origin}/mcp`,
      headers: { authorization: `Bearer ${await ownerBearer()}`, ...headers },
    }),
  );

const ownerTools = async () => administrationTools(handle, origin, await ownerBearer());

test("HTTP and MCP share administration contracts, writes, secrets and revocation", async () => {
  const discovery = await mcp("tools/list");
  expect(discovery.status).toBe(200);

  const {
    result: { tools },
  } = await discovery.json();

  expect(tools.map((tool: { name: string }) => tool.name).sort()).toEqual(
    Administration.map((action) => action.name).sort(),
  );

  for (const name of ["setupStatus", "setupOwner", "keyList"]) {
    expect(tools).not.toEqual(expect.arrayContaining([expect.objectContaining({ name })]));
  }

  const administration = await ownerTools();

  const key = await Effect.runPromise(
    administration.createApiKey({
      name: "MCP automation",
      permissions: { [resource]: ["example:read"] },
      expiresAt: null,
    }),
  );

  expect(key.key).toMatch(/^clankerauth_/);
  expect(await verify(key.key)).toMatchObject({ actor: { kind: "key", keyId: key.keyId } });
  const listing = await call("/api/listApiKeys", {});
  expect(await listing.json()).toMatchObject({
    keys: [{ keyId: key.keyId, name: "MCP automation" }],
  });
  const mcpListing = await mcp("tools/call", { name: "listApiKeys", arguments: {} });
  expect(await mcpListing.text()).not.toContain(key.key);

  expect(
    (
      await call("/api/updateApiKey", {
        keyId: key.keyId,
        name: "HTTP rename",
      })
    ).status,
  ).toBe(200);
  expect(await Effect.runPromise(administration.listApiKeys())).toMatchObject({
    keys: [{ keyId: key.keyId, name: "HTTP rename" }],
  });
  expect(
    await Effect.runPromise(administration.updateApiKey({ keyId: key.keyId, enabled: false })),
  ).toMatchObject({ keyId: key.keyId, enabled: false });
  expect(await verify(key.key)).toBe("Unauthorized");

  // Input that decodes but cannot be served is the built-in `InvalidInput`, naming the field.
  const refused = await Effect.runPromise(
    Effect.flip(
      administration.createResource({ identifier: "not a URL", name: "Invalid", scopes: [] }),
    ),
  );

  expect(refused instanceof Action.InvalidInput ? refused.issues : refused).toEqual([
    {
      path: ["identifier"],
      message: "Resource identifiers must be absolute URIs in canonical form, without a fragment",
    },
  ]);
});

test("HTTP and MCP sanitize invalid managed-client output", async () => {
  const created = await call("/api/createClient", {
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

  const listing = await call("/api/listClients", {});
  expect(listing.status).toBe(500);

  const expected = Schema.encodeSync(InternalServerError)(
    new InternalServerError({ error: "Request could not be completed" }),
  );

  expect(await listing.json()).toEqual(expected);

  const administration = await ownerTools();
  const tool = await Effect.runPromise(Effect.flip(administration.listClients()));
  expect(tool).toEqual(new InternalServerError({ error: "Request could not be completed" }));
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

  const listing = await call("/api/listApiKeys", {});
  expect(listing.status).toBe(200);
  expect((await listing.json()).keys).toEqual([
    expect.objectContaining({ keyId: key.keyId, permissions: {} }),
    expect.objectContaining({ keyId: intact.keyId, permissions: { [resource]: ["example:read"] } }),
  ]);
  expect((await call("/api/deleteApiKey", { keyId: key.keyId })).status).toBe(200);
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

  expect((await call("/api/listClients", {}, { cookie: "" })).status).toBe(401);
  expect((await mcp("tools/list", {}, { cookie: "" })).status).toBe(200);

  // The SameSite session cookie is the CSRF boundary; owner actions do not inspect Origin.
  for (const origin of ["https://evil.example", ""])
    expect((await call("/api/listClients", {}, { origin })).status).toBe(200);
  // MCP validates Origin as the protocol requires.
  expect((await mcp("tools/list", {}, { origin: "https://evil.example" })).status).toBe(403);

  const key = await create();
  expect(
    (await mcp("tools/list", {}, { cookie: "", authorization: `Bearer ${key.key}` })).status,
  ).toBe(401);
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
          Administration.map((action) => action.name).sort(),
        );
        const listing = await client.callTool({ name: "listClients", arguments: {} });
        expect(listing.isError).toBe(false);
        expect(listing.structuredContent).toMatchObject({
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
        });
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
  const permissions = { [`${origin}/`]: ["clankerauth:write"] };

  const created = await call("/api/createApiKey", {
    name: "Invalid administration key",
    permissions,
    expiresAt: null,
  });

  expect(created.status).toBe(400);
  expect((await created.json()).issues).toEqual([
    {
      path: ["permissions", `${origin}/`],
      message: "Administration requires OAuth access tokens, not API keys",
    },
  ]);
  const key = await create();
  expect((await call("/api/updateApiKey", { keyId: key.keyId, permissions })).status).toBe(400);
  expect(await verify(key.key)).toMatchObject({ scopes: ["example:read"] });
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
