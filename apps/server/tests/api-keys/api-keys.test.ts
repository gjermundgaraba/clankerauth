import { it } from "@effect/vitest";
import { nodeHandler } from "../../src/http/application.ts";
import { expect } from "vite-plus/test";
import { administrationTools, webMcpRequest, withMcpClient } from "../mcp.ts";
import { administrationResource, mcpOAuthGrant } from "../mcp-oauth-helper.ts";
import { Config, ConfigProvider, Context, Effect, Layer, Result, Schema } from "effect";
import { FetchHttpClient } from "effect/http";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import type * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import * as Testing from "@gjermundgaraba/effect-actions/Testing";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import * as KeyList from "@gjermundgaraba/clankerauth-sdk/key-list";
import * as Credentials from "@gjermundgaraba/clankerauth-sdk/credentials";
import {
  Administration,
  InternalServerError,
  OwnerHttp,
} from "@gjermundgaraba/clankerauth-admin-api";
import { listen } from "../../src/platform/node-http.ts";
import { signIn, testWebApplication, WebApplication } from "../test-issuer.ts";
import { Database } from "../../src/platform/sqlite.ts";
import { OwnerAccount } from "../../src/owner/owner.ts";

const origin = "http://localhost:3000";

const resource = "https://example.internal/api";

const CreatedApiKey = Schema.Struct({ key: Schema.String, keyId: Schema.String });

type TestRequestBody = typeof Schema.JsonObject.Type;

class OwnerCookie extends Context.Service<OwnerCookie, string>()("api-keys.test/OwnerCookie") {}

class OwnerBearer extends Context.Service<OwnerBearer, string>()("api-keys.test/OwnerBearer") {}

const send = (
  cookie: string,
  path: string,
  body?: TestRequestBody,
  headers: Record<string, string> = {},
) =>
  Effect.flatMap(WebApplication, (handle) =>
    Effect.promise(() =>
      handle(
        new Request(`${origin}${path}`, {
          method: body === undefined ? "GET" : "POST",
          headers: { origin, cookie, "content-type": "application/json", ...headers },
          body: body === undefined ? undefined : JSON.stringify(body),
        }),
      ),
    ),
  );

const call = (path: string, body?: TestRequestBody, headers: Record<string, string> = {}) =>
  Effect.flatMap(OwnerCookie, (cookie) => send(cookie, path, body, headers));

const json = (response: Response) => Effect.promise(() => response.json());

const text = (response: Response) => Effect.promise(() => response.text());

const keyList = (target = resource) => call("/api/keyList", { resource: target }, { cookie: "" });

const verify = (key: string, target = resource) =>
  Effect.gen(function* () {
    const handle = yield* WebApplication;
    const loopback: typeof fetch = (input, init) => handle(new Request(input, init));

    const result = yield* Effect.result(
      Effect.flatMap(
        Verifier.make({
          issuer: `${origin}/api/auth`,
          resource: target,
          store: Verifier.store(),
        }),
        (verifier) => verifier.verifyToken(key),
      ),
    ).pipe(
      Effect.provide(
        FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, loopback))),
      ),
    );

    return Result.isSuccess(result) ? result.success : result.failure._tag;
  });

const signedInOwner = Layer.effect(
  OwnerCookie,
  Effect.gen(function* () {
    yield* (yield* OwnerAccount).create({
      email: "owner@example.internal",
      password: "test-only password123",
    });

    const cookie = yield* signIn(yield* WebApplication, origin, {
      email: "owner@example.internal",
      password: "test-only password123",
    });

    expect(
      (yield* send(cookie, "/api/putResource", {
        identifier: resource,
        name: "Example",
        scopes: ["example:read", "example:write"],
      })).status,
    ).toBe(200);

    return cookie;
  }),
);

const ownerBearer = Layer.effect(
  OwnerBearer,
  Effect.gen(function* () {
    const handle = yield* WebApplication;
    const cookie = yield* OwnerCookie;

    const { tokens } = yield* Effect.promise(() => mcpOAuthGrant(handle, origin, cookie));

    return tokens.access_token;
  }),
);

const apiKeysIssuer = () =>
  signedInOwner.pipe(Layer.provideMerge(testWebApplication({ baseURL: origin })));

const bearerIssuer = () => ownerBearer.pipe(Layer.provideMerge(apiKeysIssuer()));

const create = Effect.gen(function* () {
  const response = yield* call("/api/createApiKey", {
    name: "Automation",
    permissions: { [resource]: ["example:read"] },
    expiresAt: null,
  });

  expect(response.status).toBe(201);

  return Schema.decodeUnknownSync(CreatedApiKey)(yield* json(response));
});

it.live("hash-only storage, explicit scopes, one-time display and next-list disable/delete", () =>
  Effect.gen(function* () {
    const key = yield* create;
    expect(key.key.startsWith("clankerauth_")).toBe(true);

    const stored = yield* (yield* Database).sql`SELECT key FROM apikey WHERE id = ${key.keyId}`;

    expect(stored[0]?.key).toBe(
      Buffer.from(yield* Effect.promise(() => KeyList.digest(key.key))).toString("base64url"),
    );
    const list = yield* call("/api/listApiKeys", {});
    expect(yield* text(list)).not.toContain(key.key);
    expect(yield* verify(key.key)).toEqual({
      subject: yield* (yield* OwnerAccount).find(),
      scopes: ["example:read"],
      actor: { kind: "key", keyId: key.keyId },
      expiresAt: undefined,
    });
    expect(yield* verify(key.key, "https://other.internal/api")).toBe("Unauthorized");
    expect((yield* call("/api/updateApiKey", { keyId: key.keyId, enabled: false })).status).toBe(
      200,
    );
    expect(yield* verify(key.key)).toBe("Unauthorized");
    expect((yield* call("/api/updateApiKey", { keyId: key.keyId, enabled: true })).status).toBe(
      200,
    );
    expect(yield* verify(key.key)).toMatchObject({ scopes: ["example:read"] });
    expect((yield* call("/api/deleteApiKey", { keyId: key.keyId })).status).toBe(200);
    expect(yield* verify(key.key)).toBe("Unauthorized");
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live(
  "a key list is signed for its resource, never cached, and reveals nothing without the key",
  () =>
    Effect.gen(function* () {
      const key = yield* create;
      const owner = yield* (yield* OwnerAccount).find();
      const response = yield* keyList();
      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      const { list } = yield* json(response);
      expect(decodeProtectedHeader(list)).toMatchObject({ alg: "EdDSA", typ: KeyList.type });
      const claims = decodeJwt(list);
      expect(claims).toMatchObject({ iss: `${origin}/api/auth`, aud: resource });
      expect((claims.exp ?? 0) - (claims.iat ?? 0)).toBe(KeyList.lifetime);
      const entries = Schema.decodeUnknownSync(KeyList.Claims)(claims).keys;
      expect(entries).toHaveLength(1);
      expect(Object.keys(entries[0] ?? {}).sort()).toEqual(["id", "sealed"]);
      const sealed = Buffer.from(entries[0]?.sealed ?? "", "base64url").toString("latin1");

      for (const secret of [key.keyId, owner ?? "", "example:read"])
        expect(sealed).not.toContain(secret);

      yield* (yield* Database)
        .sql`UPDATE apikey SET permissions = ${JSON.stringify({ [resource]: ["example:read"], [`${origin}/`]: ["clankerauth:write"] })} WHERE id = ${key.keyId}`;

      for (const target of ["https://unknown.internal/api", `${origin}/`]) {
        const empty = yield* keyList(target);
        expect(empty.status).toBe(200);
        expect(decodeJwt((yield* json(empty)).list)).toMatchObject({ aud: target, keys: [] });
      }

      expect(yield* verify(key.key, `${origin}/`)).toBe("Unauthorized");
    }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live(
  "a fresh issuer's first key list and a JWKS read beside it share one signing key, which the JWKS publishes",
  () =>
    Effect.gen(function* () {
      const [jwks, listed] = yield* Effect.all([call("/api/auth/jwks"), keyList()], {
        concurrency: "unbounded",
      });

      const { keys } = yield* json(jwks);
      expect(keys).toHaveLength(1);
      expect(keys[0].kid).toBe(decodeProtectedHeader((yield* json(listed)).list).kid);
    }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live(
  "keys cannot authenticate the dashboard's binding, create sessions or reach plugin routes",
  () =>
    Effect.gen(function* () {
      const key = yield* create;
      expect(
        (yield* call("/api/listApiKeys", {}, { cookie: "", authorization: `Bearer ${key.key}` }))
          .status,
      ).toBe(401);
      expect(
        (yield* call("/api/listApiKeys", {}, { cookie: "", "x-api-key": key.key })).status,
      ).toBe(401);
      expect((yield* call("/api/auth/api-key/create", { name: "Forbidden" })).status).toBe(404);
      expect(yield* verify("clankerauth_invalid")).toBe("Unauthorized");
    }).pipe(Effect.provide(apiKeysIssuer())),
);

const administration = `${origin}/`;

const owner = (action: string, body: TestRequestBody, key: string) =>
  send("", `/api/owner/${action}`, body, { authorization: `Bearer ${key}` });

const createAdministrationKey = (scopes: ReadonlyArray<string>, by?: string) =>
  Effect.gen(function* () {
    const body = {
      name: "Deployer",
      permissions: { [administration]: scopes },
      expiresAt: null,
    };

    const response =
      by === undefined
        ? yield* call("/api/createApiKey", body)
        : yield* owner("createApiKey", body, by);

    expect(response.status, yield* text(response.clone())).toBe(201);

    return Schema.decodeUnknownSync(CreatedApiKey)(yield* json(response));
  });

it.live(
  "an administration key administers at /api/owner, as its scopes allow, from its next request",
  () =>
    Effect.gen(function* () {
      const key = yield* createAdministrationKey(["clankerauth:read", "clankerauth:write"]);
      expect((yield* owner("listApiKeys", {}, (yield* create).key)).status).toBe(401);
      expect((yield* owner("listApiKeys", {}, "clankerauth_invalid")).status).toBe(401);

      expect((yield* owner("listApiKeys", {}, key.key)).status).toBe(200);
      expect(
        (yield* call("/api/listApiKeys", {}, { cookie: "", authorization: `Bearer ${key.key}` }))
          .status,
      ).toBe(401);

      const notes = {
        identifier: "https://notes.internal/",
        name: "Notes",
        scopes: ["notes:read"],
      };

      expect((yield* owner("putResource", notes, key.key)).status).toBe(200);
      expect(
        yield* json(yield* owner("getResource", { identifier: notes.identifier }, key.key)),
      ).toMatchObject(notes);
      expect(decodeJwt((yield* json(yield* keyList(administration))).list).keys).toEqual([]);

      expect(
        (yield* call("/api/updateApiKey", {
          keyId: key.keyId,
          permissions: { [administration]: ["clankerauth:read"] },
        })).status,
      ).toBe(200);
      expect((yield* owner("listApiKeys", {}, key.key)).status).toBe(200);
      const refused = yield* owner("deleteResource", { identifier: notes.identifier }, key.key);
      expect(refused.status).toBe(403);
      expect((yield* json(refused))._tag).toBe("Forbidden");

      expect((yield* call("/api/updateApiKey", { keyId: key.keyId, enabled: false })).status).toBe(
        200,
      );
      expect((yield* owner("listApiKeys", {}, key.key)).status).toBe(401);
      expect((yield* call("/api/updateApiKey", { keyId: key.keyId, enabled: true })).status).toBe(
        200,
      );
      expect((yield* owner("listApiKeys", {}, key.key)).status).toBe(200);

      yield* (yield* Database)
        .sql`UPDATE apikey SET expiresAt = ${new Date(Date.now() - 1000).toISOString()} WHERE id = ${key.keyId}`;
      expect((yield* owner("listApiKeys", {}, key.key)).status).toBe(401);
    }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("an administration key creates and deletes administration keys, itself among them", () =>
  Effect.gen(function* () {
    const key = yield* createAdministrationKey(["clankerauth:read", "clankerauth:write"]);
    const child = yield* createAdministrationKey(["clankerauth:write"], key.key);
    expect((yield* owner("listApiKeys", {}, child.key)).status).toBe(200);
    expect((yield* owner("deleteApiKey", { keyId: child.keyId }, key.key)).status).toBe(200);
    expect((yield* owner("listApiKeys", {}, child.key)).status).toBe(401);
    expect((yield* owner("deleteApiKey", { keyId: key.keyId }, key.key)).status).toBe(200);
    expect((yield* owner("listApiKeys", {}, key.key)).status).toBe(401);
    expect((yield* json(yield* call("/api/listApiKeys", {}))).keys).toEqual([]);
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("an administration key calls administration tools over MCP", () =>
  Effect.gen(function* () {
    const key = yield* createAdministrationKey(["clankerauth:read"]);
    const handle = yield* WebApplication;
    const tools = yield* administrationTools(handle, origin, key.key);
    expect((yield* tools.listApiKeys()).keys).toHaveLength(1);
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("a program's administration client sends the key the environment gives", () =>
  Effect.gen(function* () {
    const key = yield* createAdministrationKey(["clankerauth:read"]);

    const client = yield* ActionHttp.client(OwnerHttp, {
      baseUrl: origin,
      transformClient: Credentials.authorizing({
        url: administration,
        token: Config.Redacted("CLANKERAUTH_TOKEN"),
      }),
    }).pipe(Effect.provide(Testing.layer(yield* WebApplication)));

    const listed = yield* client
      .listApiKeys()
      .pipe(
        Effect.provide(
          ConfigProvider.layer(ConfigProvider.fromEnvRecord({ CLANKERAUTH_TOKEN: key.key })),
        ),
      );

    expect(listed.keys.map((entry) => entry.keyId)).toEqual([key.keyId]);
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("one key reaches several resources, each with only its own scopes", () =>
  Effect.gen(function* () {
    const host = "https://host.example.internal/";
    expect(
      (yield* call("/api/putResource", {
        identifier: host,
        name: "Host",
        scopes: ["host:read", "host:write"],
      })).status,
    ).toBe(200);

    const created = yield* call("/api/createApiKey", {
      name: "Controller",
      permissions: { [resource]: ["example:read"], [host]: ["host:write"] },
      expiresAt: null,
    });

    const key = Schema.decodeUnknownSync(CreatedApiKey)(yield* json(created));
    expect(yield* verify(key.key)).toMatchObject({ scopes: ["example:read"] });
    expect(yield* verify(key.key, host)).toMatchObject({ scopes: ["host:write"] });

    const example = yield* create;
    expect(yield* verify(example.key, host)).toBe("Unauthorized");
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("resource policy removal and restoration retains only explicit grants", () =>
  Effect.gen(function* () {
    const key = yield* create;
    yield* call("/api/putResource", {
      identifier: resource,
      name: "Example",
      scopes: ["example:write"],
    });
    expect(yield* verify(key.key)).toBe("Unauthorized");
    yield* call("/api/putResource", {
      identifier: resource,
      name: "Example",
      scopes: ["example:read", "example:write", "example:new"],
    });
    expect(yield* verify(key.key)).toMatchObject({ scopes: ["example:read"] });
    yield* call("/api/deleteResource", { identifier: resource });
    expect(yield* verify(key.key)).toBe("Unauthorized");
    yield* call("/api/putResource", {
      identifier: resource,
      name: "Example",
      scopes: ["example:read", "example:write"],
    });
    expect(yield* verify(key.key)).toMatchObject({ scopes: ["example:read"] });
    yield* call("/api/updateApiKey", {
      keyId: key.keyId,
      permissions: { [resource]: ["example:write"] },
    });
    expect(yield* verify(key.key)).toMatchObject({ scopes: ["example:write"] });
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("expired keys leave the key list", () =>
  Effect.gen(function* () {
    const key = yield* create;
    expect(yield* verify(key.key)).toMatchObject({ scopes: ["example:read"] });
    expect(decodeJwt((yield* json(yield* keyList())).list).keys).toHaveLength(1);
    yield* (yield* Database)
      .sql`UPDATE apikey SET expiresAt = ${new Date(Date.now() - 1000).toISOString()} WHERE id = ${key.keyId}`;
    expect(decodeJwt((yield* json(yield* keyList())).list).keys).toEqual([]);
    expect(yield* verify(key.key)).toBe("Unauthorized");
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("creation rejects implicit, unknown and invalid expiry grants, naming the field", () =>
  Effect.gen(function* () {
    const unknown = "https://unknown.internal";

    const rejected: ReadonlyArray<readonly [TestRequestBody, ReadonlyArray<string>]> = [
      [{ name: "Bad", permissions: {}, expiresAt: null }, ["permissions"]],
      [
        { name: "Bad", permissions: { [resource]: [] }, expiresAt: null },
        ["permissions", resource],
      ],
      [
        { name: "Bad", permissions: { [resource]: ["example:unknown"] }, expiresAt: null },
        ["permissions", resource],
      ],
      [
        { name: "Bad", permissions: { [unknown]: ["example:read"] }, expiresAt: null },
        ["permissions", unknown],
      ],
      [{ name: "", permissions: { [resource]: ["example:read"] }, expiresAt: null }, ["name"]],
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
      const response = yield* call("/api/createApiKey", body);
      expect(response.status).toBe(400);
      const refused = yield* json(response);
      expect(refused._tag).toBe("InvalidInput");
      expect(refused.issues.map((issue: { readonly path: unknown }) => issue.path)).toContainEqual(
        path,
      );
    }
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("expiry travels as an ISO timestamp all the way to key verification", () =>
  Effect.gen(function* () {
    const sent = Date.now();
    const requested = sent + 86_400_000;

    const response = yield* call("/api/createApiKey", {
      name: "Expiring",
      permissions: { [resource]: ["example:read"] },
      expiresAt: new Date(requested).toISOString(),
    });

    expect(response.status).toBe(201);
    const created = yield* json(response);
    // why: the plugin dates a lifetime in whole seconds itself, so expiry drifts by the request
    expect(Date.parse(created.expiresAt)).toBeGreaterThanOrEqual(requested - 1);
    expect(Date.parse(created.expiresAt)).toBeLessThanOrEqual(requested + (Date.now() - sent));
    expect(Date.parse(created.createdAt)).toBeLessThanOrEqual(Date.now());
    const expiresAt: string = created.expiresAt;
    const listed = yield* json(yield* call("/api/listApiKeys", {}));
    expect(listed.keys).toEqual([expect.objectContaining({ keyId: created.keyId, expiresAt })]);
    expect(yield* verify(created.key)).toMatchObject({ expiresAt: Date.parse(expiresAt) });
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("listing returns key metadata without plaintext", () =>
  Effect.gen(function* () {
    const created = [];

    for (let index = 0; index < 5; index++) created.push(yield* create);
    const response = yield* call("/api/listApiKeys", {});
    expect(response.status).toBe(200);
    const body = yield* json(response);
    expect(body.keys).toHaveLength(created.length);
    expect(new Set(body.keys.map((key: { keyId: string }) => key.keyId))).toEqual(
      new Set(created.map((key) => key.keyId)),
    );

    for (const key of created) expect(JSON.stringify(body)).not.toContain(key.key);
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("key writes require owner authorization", () =>
  Effect.gen(function* () {
    const key = yield* create;
    expect((yield* call("/api/updateApiKey", { keyId: key.keyId, name: "Renamed" })).status).toBe(
      200,
    );
    expect(
      (yield* call("/api/updateApiKey", { keyId: key.keyId, enabled: false }, { cookie: "" }))
        .status,
    ).toBe(401);
  }).pipe(Effect.provide(apiKeysIssuer())),
);

const mcp = (method: string, params: ActionMcp.Params = {}, headers: Record<string, string> = {}) =>
  Effect.gen(function* () {
    const handle = yield* WebApplication;
    const bearer = yield* OwnerBearer;

    return yield* Effect.promise(() =>
      handle(
        webMcpRequest({
          method,
          params,
          url: `${origin}/mcp`,
          headers: { authorization: `Bearer ${bearer}`, ...headers },
        }),
      ),
    );
  });

const ownerTools = Effect.gen(function* () {
  const handle = yield* WebApplication;

  return yield* administrationTools(handle, origin, yield* OwnerBearer);
});

it.live("MCP administration advertises no list changes and refuses subscriptions", () =>
  Effect.gen(function* () {
    const discovery = yield* mcp("server/discover");
    expect(discovery.status).toBe(200);
    expect((yield* json(discovery)).result.capabilities.tools).toEqual({ listChanged: false });

    const listen = yield* text(
      yield* mcp("subscriptions/listen", { notifications: { toolsListChanged: true } }),
    );

    expect(JSON.parse(listen.replace(/^data: /m, "").trim()).error.code).toBe(-32601);
  }).pipe(Effect.provide(bearerIssuer())),
);

it.live("HTTP and MCP share administration contracts, writes, secrets and revocation", () =>
  Effect.gen(function* () {
    const discovery = yield* mcp("tools/list");
    expect(discovery.status).toBe(200);

    const {
      result: { tools },
    } = yield* json(discovery);

    expect(tools.map((tool: { name: string }) => tool.name).sort()).toEqual(
      Administration.map((action) => action.name).sort(),
    );

    for (const name of ["setupStatus", "setupOwner", "keyList"]) {
      expect(tools).not.toEqual(expect.arrayContaining([expect.objectContaining({ name })]));
    }

    const administration = yield* ownerTools;

    const key = yield* administration.createApiKey({
      name: "MCP automation",
      permissions: { [resource]: ["example:read"] },
      expiresAt: null,
    });

    expect(key.key).toMatch(/^clankerauth_/);
    expect(yield* verify(key.key)).toMatchObject({ actor: { kind: "key", keyId: key.keyId } });
    const listing = yield* call("/api/listApiKeys", {});
    expect(yield* json(listing)).toMatchObject({
      keys: [{ keyId: key.keyId, name: "MCP automation" }],
    });
    const mcpListing = yield* mcp("tools/call", { name: "listApiKeys", arguments: {} });
    expect(yield* text(mcpListing)).not.toContain(key.key);

    expect(
      (yield* call("/api/updateApiKey", {
        keyId: key.keyId,
        name: "HTTP rename",
      })).status,
    ).toBe(200);
    expect(yield* administration.listApiKeys()).toMatchObject({
      keys: [{ keyId: key.keyId, name: "HTTP rename" }],
    });
    expect(yield* administration.updateApiKey({ keyId: key.keyId, enabled: false })).toMatchObject({
      keyId: key.keyId,
      enabled: false,
    });
    expect(yield* verify(key.key)).toBe("Unauthorized");

    const refused = yield* Effect.flip(
      administration.putResource({ identifier: "not a URL", name: "Invalid", scopes: [] }),
    );

    expect(refused instanceof Action.InvalidInput ? refused.issues : refused).toEqual([
      {
        path: ["identifier"],
        message: "Resource identifiers must be absolute URIs in canonical form, without a fragment",
      },
    ]);
  }).pipe(Effect.provide(bearerIssuer())),
);

it.live("HTTP and MCP sanitize invalid managed-client output", () =>
  Effect.gen(function* () {
    const created = yield* call("/api/createClient", {
      client_name: "Corrupt-output test",
      redirect_uris: ["http://127.0.0.1:9876/callback"],
      resources: [],
      application_type: "native",
      token_endpoint_auth_method: "client_secret_basic",
    });

    expect(created.status).toBe(201);
    const { client_id } = yield* json(created);
    yield* (yield* Database)
      .sql`UPDATE oauthClient SET redirectUris = ${JSON.stringify([42])} WHERE clientId = ${client_id}`;

    const listing = yield* call("/api/listClients", {});
    expect(listing.status).toBe(500);

    const expected = Schema.encodeSync(InternalServerError)(
      new InternalServerError({ message: "Request could not be completed" }),
    );

    expect(yield* json(listing)).toEqual(expected);

    const administration = yield* ownerTools;
    const tool = yield* Effect.flip(administration.listClients());
    expect(tool).toEqual(new InternalServerError({ message: "Request could not be completed" }));
  }).pipe(Effect.provide(bearerIssuer())),
);

it.live(
  "a key with malformed stored permissions grants nothing, stays listed and can be deleted",
  () =>
    Effect.gen(function* () {
      const key = yield* create;
      const intact = yield* create;
      yield* (yield* Database)
        .sql`UPDATE apikey SET permissions = ${JSON.stringify({ [resource]: [42] })} WHERE id = ${key.keyId}`;

      expect(yield* verify(key.key)).toBe("Unauthorized");
      expect((yield* owner("listApiKeys", {}, key.key)).status).toBe(401);
      expect(yield* verify(intact.key)).toMatchObject({
        actor: { kind: "key", keyId: intact.keyId },
      });

      const listing = yield* call("/api/listApiKeys", {});
      expect(listing.status).toBe(200);
      expect((yield* json(listing)).keys).toEqual([
        expect.objectContaining({ keyId: key.keyId, permissions: {} }),
        expect.objectContaining({
          keyId: intact.keyId,
          permissions: { [resource]: ["example:read"] },
        }),
      ]);
      expect((yield* call("/api/deleteApiKey", { keyId: key.keyId })).status).toBe(200);
    }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("a key row that decodes but cannot be sealed is left out on its own", () =>
  Effect.gen(function* () {
    const { sql } = yield* Database;
    const key = yield* create;
    const intact = yield* create;
    yield* sql`UPDATE apikey SET referenceId = '' WHERE id = ${key.keyId}`;

    expect(yield* verify(key.key)).toBe("Unauthorized");
    expect(yield* verify(intact.key)).toMatchObject({
      actor: { kind: "key", keyId: intact.keyId },
    });
    yield* sql`DELETE FROM apikey WHERE id = ${key.keyId}`;
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("HTTP administration requires the owner session; MCP requires bearer authorization", () =>
  Effect.gen(function* () {
    const userId = yield* (yield* OwnerAccount).find();

    if (userId === undefined)
      return yield* Effect.die(new Error("Expected an owner for spoofed-session checks"));
    const spoofedOwner = { userId, cookie: yield* OwnerCookie };
    expect((yield* call("/api/listClients", spoofedOwner, { cookie: "" })).status).toBe(401);
    expect(
      (yield* mcp(
        "tools/call",
        { name: "listClients", arguments: spoofedOwner },
        { authorization: "" },
      )).status,
    ).toBe(401);

    expect((yield* call("/api/listClients", {}, { cookie: "" })).status).toBe(401);
    expect((yield* mcp("tools/list", {}, { cookie: "" })).status).toBe(200);

    // why: the SameSite session cookie is the CSRF boundary, so owner actions ignore Origin
    for (const origin of ["https://evil.example", ""])
      expect((yield* call("/api/listClients", {}, { origin })).status).toBe(200);
    expect((yield* mcp("tools/list", {}, { origin: "https://evil.example" })).status).toBe(403);

    const key = yield* create;
    expect(
      (yield* mcp("tools/list", {}, { cookie: "", authorization: `Bearer ${key.key}` })).status,
    ).toBe(401);
  }).pipe(Effect.provide(bearerIssuer())),
);

it.live(
  "official 2026-07-28 MCP client uses OAuth bearer authentication through native Effect HTTP",
  () =>
    Effect.gen(function* () {
      const handle = yield* WebApplication;
      const cookie = yield* OwnerCookie;
      const { tokens } = yield* Effect.promise(() => mcpOAuthGrant(handle, origin, cookie));

      yield* Effect.scoped(
        Effect.gen(function* () {
          const { port, serve } = yield* listen(0, "127.0.0.1");
          yield* serve(yield* nodeHandler());
          yield* Effect.promise(() =>
            withMcpClient(
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
            ),
          );
        }),
      );
    }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("administration grants take only administration's own scopes", () =>
  Effect.gen(function* () {
    for (const scope of ["offline_access", "example:read"]) {
      const created = yield* call("/api/createApiKey", {
        name: "Invalid administration key",
        permissions: { [`${origin}/`]: [scope] },
        expiresAt: null,
      });

      expect(created.status).toBe(400);
      expect((yield* json(created)).issues).toEqual([
        {
          path: ["permissions", `${origin}/`],
          message: "Select explicitly granted, currently available Resource scopes",
        },
      ]);
    }

    const key = yield* create;
    const permissions = { [resource]: ["example:read"], [`${origin}/`]: ["clankerauth:read"] };
    const updated = yield* call("/api/updateApiKey", { keyId: key.keyId, permissions });
    expect(updated.status).toBe(200);
    expect((yield* json(updated)).permissions).toEqual(permissions);
    expect(yield* verify(key.key)).toMatchObject({ scopes: ["example:read"] });
  }).pipe(Effect.provide(apiKeysIssuer())),
);

it.live("renaming a key preserves grants for resources that are no longer available", () =>
  Effect.gen(function* () {
    const key = yield* create;
    expect((yield* call("/api/deleteResource", { identifier: resource })).status).toBe(200);
    expect((yield* call("/api/updateApiKey", { keyId: key.keyId, name: "Renamed" })).status).toBe(
      200,
    );
    const { keys } = yield* json(yield* call("/api/listApiKeys", {}));
    expect(keys[0]).toMatchObject({
      name: "Renamed",
      permissions: { [resource]: ["example:read"] },
    });
  }).pipe(Effect.provide(apiKeysIssuer())),
);
