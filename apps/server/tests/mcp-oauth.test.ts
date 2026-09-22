import { afterEach, beforeEach, expect, test, vi } from "vite-plus/test";
import { mcpRequest } from "@gjermundgaraba/effect-actions/Testing";
import { withMcpClient } from "@gjermundgaraba/effect-actions/TestingClient";
import { Effect, Exit, Schema, Scope } from "effect";
import { InternalServerError } from "@clankerauth/admin-api";
import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { nodeHandler } from "../src/app.ts";
import { createNodeServer } from "../src/node-http.ts";
import { webApplication as application } from "./web-application.ts";
import { createOwner } from "../src/auth.ts";
import { openIssuer, type Issuer } from "./issuer.ts";
import { administrationResource, mcpOAuthGrant, oauthToken } from "./mcp-oauth-helper.ts";

const baseURL = "http://localhost:3000";

const ListenAddress = Schema.Struct({ port: Schema.Number });

type JsonPrimitive = string | number | boolean | null;

type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };

type TestRequestBody = { readonly [key: string]: JsonValue };

type ClientActionPayload = {
  client_id: string;
  blocked?: boolean;
};

type PrivateKeyRegistration = {
  client_name: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  grant_types: string[];
  response_types: string[];
  jwks?: { keys: object[] };
};

let issuer: Issuer;

let handle: ReturnType<typeof application>;

let cookie: string;

const admin = (action: string, body: TestRequestBody) =>
  handle(
    new Request(`${baseURL}/api/administration/${action}`, {
      method: "POST",
      headers: { cookie, origin: baseURL, "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  );

const mcp = (token?: string, headers: Record<string, string> = {}) =>
  handle(
    mcpRequest({
      method: "tools/list",
      url: `${baseURL}/mcp`,
      headers: token === undefined ? headers : { ...headers, authorization: `Bearer ${token}` },
    }),
  );

const refresh = (client_id: string, refresh_token: string) =>
  oauthToken(handle, baseURL, {
    grant_type: "refresh_token",
    client_id,
    refresh_token,
    resource: `${baseURL}/mcp`,
  });

beforeEach(async () => {
  issuer = await openIssuer({ baseURL });
  handle = application(issuer.service);
  await issuer.run(
    createOwner(issuer.service, {
      email: "owner@example.internal",
      password: "test-only password123",
    }),
  );

  const login = await handle(
    new Request(`${baseURL}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { origin: baseURL, "content-type": "application/json" },
      body: JSON.stringify({ email: "owner@example.internal", password: "test-only password123" }),
    }),
  );

  expect(login.status).toBe(200);
  cookie = login.headers
    .getSetCookie()
    .map((part) => part.split(";")[0])
    .join("; ");
});

afterEach(async () => {
  vi.useRealTimers();
  await handle.dispose();
  await issuer.close();
});

test("anonymous discovery leads to PKCE owner consent, bearer administration, and refresh", async () => {
  const unauthorized = await mcp();
  expect(unauthorized.status).toBe(401);
  const challenge = unauthorized.headers.get("www-authenticate");
  expect(challenge).toContain("Bearer");
  // RFC 6750: no error code when the request carried no credentials.
  expect(challenge).not.toContain("error=");
  const metadataURL = /resource_metadata="([^"]+)"/.exec(challenge ?? "")?.[1];
  expect(metadataURL).toBe(`${baseURL}/.well-known/oauth-protected-resource/mcp`);
  const metadata = await handle(new Request(metadataURL ?? ""));
  expect(metadata.status).toBe(200);
  expect(await metadata.json()).toMatchObject({
    resource: `${baseURL}/mcp`,
    authorization_servers: [`${baseURL}/api/auth`],
    scopes_supported: ["admin", "offline_access"],
    bearer_methods_supported: ["header"],
  });

  const discovery = await handle(
    new Request(`${baseURL}/.well-known/oauth-authorization-server/api/auth`),
  );

  expect(discovery.status).toBe(200);
  expect(await discovery.json()).toMatchObject({
    issuer: `${baseURL}/api/auth`,
    authorization_endpoint: `${baseURL}/api/auth/oauth2/authorize`,
    token_endpoint: `${baseURL}/api/auth/oauth2/token`,
    registration_endpoint: `${baseURL}/api/auth/oauth2/register`,
    code_challenge_methods_supported: ["S256"],
  });
  const { client_id, tokens } = await mcpOAuthGrant(handle, baseURL, cookie);
  expect((await mcp(tokens.access_token)).status).toBe(200);

  // The token grants MCP access only; browser administration still requires its own session.
  const http = await handle(
    new Request(`${baseURL}/api/administration/listClients`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${tokens.access_token}`,
        "content-type": "application/json",
      },
      body: "{}",
    }),
  );

  expect(http.status).toBe(401);
  await withMcpClient(
    {
      fetch: handle,
      versionNegotiation: { mode: { pin: "2026-07-28" } },
      path: "/mcp",
      baseUrl: baseURL,
      headers: { authorization: `Bearer ${tokens.access_token}` },
    },
    async (client) => {
      const created = await client.callTool({
        name: "createClient",
        arguments: {
          client_name: "Created through MCP",
          redirect_uris: ["http://127.0.0.1:9912/callback"],
          resources: [],
          application_type: "native",
          token_endpoint_auth_method: "client_secret_basic",
        },
      });

      expect(created.isError).toBe(false);
      expect(created.structuredContent).toMatchObject({
        value: { client_secret: expect.any(String) },
      });
      const listing = await client.callTool({ name: "listClients", arguments: {} });
      expect(listing.isError).toBe(false);
      expect(JSON.stringify(listing.structuredContent)).not.toContain('"client_secret":');
    },
  );
  const rotated = await refresh(client_id, tokens.refresh_token);
  expect(rotated.status, await rotated.clone().text()).toBe(200);
  const replacement = await rotated.json();
  expect(replacement.refresh_token).not.toBe(tokens.refresh_token);
  expect((await mcp(replacement.access_token)).status).toBe(200);
});

test("an aborted MCP tool call settles its provider work and compensation before shutdown", async () => {
  const { tokens } = await mcpOAuthGrant(handle, baseURL, cookie);
  const { api } = issuer.service.auth;
  const createClient = api.adminCreateOAuthClient;
  const deleteClient = api.deleteOAuthClient;
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const controller = new AbortController();
  let compensated = false;
  let stopped = false;
  vi.spyOn(api, "adminCreateOAuthClient").mockImplementation(async (context) => {
    entered.resolve();
    await release.promise;

    return createClient(context);
  });
  // Fail once the provider has created the client, so the handler has to remove it again.
  vi.spyOn(issuer.service.resources, "setAccess").mockReturnValue(
    Effect.fail(new InternalServerError({ error: "Request could not be completed" })),
  );
  vi.spyOn(api, "deleteOAuthClient").mockImplementation(async (context) => {
    const deleted = await deleteClient(context);
    compensated = true;

    return deleted;
  });

  // Serve and shut down the way main.ts does: the server's scope owns its request fibers.
  const scope = Scope.makeUnsafe();

  const server = createNodeServer(
    await issuer.run(nodeHandler().pipe(Effect.provideService(Scope.Scope, scope))),
  );

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = Schema.decodeUnknownSync(ListenAddress)(server.address());

  try {
    const request = mcpRequest({
      method: "tools/call",
      url: `http://127.0.0.1:${port}/mcp`,
      params: {
        name: "createClient",
        arguments: {
          client_name: "Aborted through MCP",
          redirect_uris: ["http://127.0.0.1:9912/callback"],
          resources: [],
          application_type: "native",
          token_endpoint_auth_method: "client_secret_basic",
        },
      },
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });

    const call = fetch(new Request(request, { signal: controller.signal }));
    await entered.promise;
    controller.abort();
    await expect(call).rejects.toThrow();

    server.close();
    server.closeAllConnections();

    const stopping = Effect.runPromise(Scope.close(scope, Exit.void)).then(() => {
      stopped = true;

      return compensated;
    });

    // Stateless MCP has no cancellation: the aborted call still owns its provider write.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(stopped).toBe(false);
    release.resolve();
    expect(await stopping).toBe(true);
  } finally {
    release.resolve();
    server.close();
    await Effect.runPromise(Scope.close(scope, Exit.void));
  }

  expect(
    await Effect.runPromise(
      issuer.service.sql`SELECT clientId FROM oauthClient WHERE name = ${"Aborted through MCP"}`,
    ),
  ).toEqual([]);
});

test("MCP rejects cookies, API keys, malformed, expired, wrong-audience, and insufficient-scope tokens", async () => {
  const rejectedHeaders: Array<Record<string, string>> = [
    { cookie },
    { authorization: "Basic invalid" },
    { authorization: "Bearer invalid" },
  ];

  for (const headers of rejectedHeaders) {
    const response = await mcp(undefined, headers);
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("resource_metadata=");
  }

  const target = "https://resource.example/api";
  expect(
    (
      await admin("createResource", {
        identifier: target,
        name: "Other audience",
        scopes: ["read"],
      })
    ).status,
  ).toBe(201);

  const created = await admin("createApiKey", {
    name: "Not an OAuth token",
    permissions: { [target]: ["read"] },
    expiresAt: null,
  });

  expect(created.status).toBe(201);
  expect((await mcp((await created.json()).key)).status).toBe(401);

  const other = await mcpOAuthGrant(handle, baseURL, cookie, {
    resource: target,
    scope: "offline_access read",
  });

  expect((await mcp(other.tokens.access_token)).status).toBe(401);

  const insufficient = await mcpOAuthGrant(handle, baseURL, cookie, {
    scope: "offline_access",
  });

  const denied = await mcp(insufficient.tokens.access_token);
  expect(denied.status).toBe(403);
  expect(denied.headers.get("www-authenticate")).toContain('error="insufficient_scope"');
  expect(denied.headers.get("www-authenticate")).toContain('scope="admin"');
  const valid = await mcpOAuthGrant(handle, baseURL, cookie);
  const parts = valid.tokens.access_token.split(".");
  parts[1] = Buffer.from(
    JSON.stringify({ sub: "not-owner", aud: `${baseURL}/mcp`, scope: "admin" }),
  ).toString("base64url");
  expect((await mcp(parts.join("."))).status).toBe(401);
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(Date.now() + (Number(valid.tokens.expires_in) + 60) * 1000);
  expect((await mcp(valid.tokens.access_token)).status).toBe(401);
});

test("administration resource permits persistent renaming but reserves its scopes and identity", async () => {
  const resource = administrationResource(baseURL);
  expect((await admin("createResource", resource)).status).toBe(400);
  expect((await admin("updateResource", { ...resource, scopes: ["everything"] })).status).toBe(400);
  expect((await admin("deleteResource", { identifier: resource.identifier })).status).toBe(400);
  const renamed = { ...resource, name: "My administration" };
  expect((await admin("updateResource", renamed)).status).toBe(200);
  await handle.dispose();
  issuer = await issuer.reopen();
  handle = application(issuer.service);
  expect((await (await admin("listClients", {})).json()).resources).toEqual([renamed]);
});

test.each(["block", "revoke"] as const)(
  "%s ends refresh at once; blocking also rejects live access tokens",
  async (operation) => {
    const { client_id, tokens } = await mcpOAuthGrant(handle, baseURL, cookie);
    expect((await mcp(tokens.access_token)).status).toBe(200);

    const payload: ClientActionPayload = { client_id };

    if (operation === "block") payload.blocked = true;

    const response = await admin(operation === "block" ? "blockClient" : "revokeClient", payload);

    expect(response.status).toBe(200);
    const afterwards = await mcp(tokens.access_token);

    if (operation === "block") {
      expect(afterwards.status).toBe(401);
      expect(afterwards.headers.get("www-authenticate")).toContain('error="invalid_token"');

      const denied = await handle(
        new Request(
          `${baseURL}/api/auth/oauth2/authorize?${new URLSearchParams({
            client_id,
            redirect_uri: "http://127.0.0.1:9876/callback",
            response_type: "code",
            resource: `${baseURL}/mcp`,
            scope: "admin",
            code_challenge: "x".repeat(43),
            code_challenge_method: "S256",
            state: "blocked",
          })}`,
          { headers: { cookie } },
        ),
      );

      expect(denied.headers.get("location") ?? "").not.toContain("/consent");
    } else {
      // Revocation clears stored grants; an already-issued access token lasts until it expires.
      expect(afterwards.status).toBe(200);
    }

    expect((await refresh(client_id, tokens.refresh_token)).status).toBe(400);

    if (operation === "block")
      expect((await admin("blockClient", { client_id, blocked: false })).status).toBe(200);

    const renewed = await mcpOAuthGrant(handle, baseURL, cookie, { clientId: client_id });
    expect((await mcp(renewed.tokens.access_token)).status).toBe(200);
  },
);

test("MCP protocol and owner-identity operations do not acquire provider sessions", async () => {
  const resource = "https://automation.example/api";
  expect(
    (
      await admin("createResource", {
        identifier: resource,
        name: "Automation",
        scopes: ["read"],
      })
    ).status,
  ).toBe(201);
  const { tokens } = await mcpOAuthGrant(handle, baseURL, cookie);
  const target = await mcpOAuthGrant(handle, baseURL, cookie);
  const { context } = issuer.service;
  const createSession = vi.spyOn(context.internalAdapter, "createSession");
  const deleteSession = vi.spyOn(context.internalAdapter, "deleteSession");
  await withMcpClient(
    {
      fetch: handle,
      versionNegotiation: { mode: { pin: "2026-07-28" } },
      path: "/mcp",
      baseUrl: baseURL,
      headers: { authorization: `Bearer ${tokens.access_token}` },
    },
    async (client) => {
      // Connecting initializes the protocol; listing tools needs no provider credentials either.
      expect((await client.listTools()).tools.length).toBeGreaterThan(0);
      expect(createSession).not.toHaveBeenCalled();

      const created = await client.callTool({
        name: "createApiKey",
        arguments: {
          name: "Owner identity only",
          permissions: { [resource]: ["read"] },
          expiresAt: null,
        },
      });

      expect(created.isError).toBe(false);

      const key = Schema.decodeUnknownSync(
        Schema.Struct({ value: Schema.Struct({ keyId: Schema.String }) }),
      )(created.structuredContent).value;

      const updated = await client.callTool({
        name: "updateApiKey",
        arguments: { keyId: key.keyId, enabled: false },
      });

      expect(updated.isError).toBe(false);

      for (const name of ["revokeClient", "blockClient"]) {
        const arguments_: ClientActionPayload = {
          client_id: target.client_id,
        };

        if (name === "blockClient") arguments_.blocked = true;

        const result = await client.callTool({
          name,
          arguments: arguments_,
        });

        expect(result.isError).toBe(false);
      }

      expect(createSession).not.toHaveBeenCalled();
      expect(deleteSession).not.toHaveBeenCalled();
    },
  );
});

test("provider-backed MCP writes release temporary sessions and offline grants survive owner sign-out", async () => {
  const { client_id, tokens } = await mcpOAuthGrant(handle, baseURL, cookie);
  const sessions = () => Effect.runPromise(issuer.service.sql`SELECT id FROM session ORDER BY id`);
  const before = await sessions();
  const { context } = issuer.service;
  const createSession = vi.spyOn(context.internalAdapter, "createSession");
  const deleteSession = vi.spyOn(context.internalAdapter, "deleteSession");
  await withMcpClient(
    {
      fetch: handle,
      versionNegotiation: { mode: { pin: "2026-07-28" } },
      path: "/mcp",
      baseUrl: baseURL,
      headers: { authorization: `Bearer ${tokens.access_token}` },
    },
    async (client) => {
      const result = await client.callTool({
        name: "createResource",
        arguments: {
          identifier: "https://temporary-session.example/api",
          name: "Created with OAuth",
          scopes: ["read"],
        },
      });

      expect(result.isError).toBe(false);

      const duplicate = await client.callTool({
        name: "createResource",
        arguments: {
          identifier: "https://temporary-session.example/api",
          name: "Duplicate",
          scopes: ["read"],
        },
      });

      expect(duplicate.isError).toBe(true);
    },
  );
  // HTTP responses may resolve before the request Scope finishes its asynchronous release.
  await expect.poll(sessions).toEqual(before);
  expect(createSession).toHaveBeenCalledTimes(2);
  expect(deleteSession).toHaveBeenCalledTimes(2);

  const logout = await handle(
    new Request(`${baseURL}/api/auth/sign-out`, {
      method: "POST",
      headers: { cookie, origin: baseURL, "content-type": "application/json" },
      body: "{}",
    }),
  );

  expect(logout.status).toBe(200);
  expect((await mcp(tokens.access_token)).status).toBe(200);
  const refreshed = await refresh(client_id, tokens.refresh_token);
  expect(refreshed.status, await refreshed.clone().text()).toBe(200);
  expect((await mcp((await refreshed.json()).access_token)).status).toBe(200);
});

test("deleting a client ends MCP access and refresh", async () => {
  const { client_id, tokens } = await mcpOAuthGrant(handle, baseURL, cookie);
  expect((await mcp(tokens.access_token)).status).toBe(200);
  await Effect.runPromise(
    Effect.gen(function* () {
      yield* issuer.service.sql`DELETE FROM oauthClientResource WHERE clientId = ${client_id}`;
      yield* issuer.service.sql`DELETE FROM oauthClient WHERE clientId = ${client_id}`;
    }),
  );
  expect((await mcp(tokens.access_token)).status).toBe(401);
  expect((await refresh(client_id, tokens.refresh_token)).status).toBe(400);
});

test("offline MCP access and refresh survive browser-session expiry and cleanup", async () => {
  const { client_id, tokens } = await mcpOAuthGrant(handle, baseURL, cookie);
  expect((await mcp(tokens.access_token)).status).toBe(200);
  await Effect.runPromise(
    issuer.service
      .sql`UPDATE session SET expiresAt = ${new Date(Date.now() - 60_000).toISOString()}`,
  );
  expect((await mcp(tokens.access_token)).status).toBe(200);
  const refreshed = await refresh(client_id, tokens.refresh_token);
  expect(refreshed.status, await refreshed.clone().text()).toBe(200);
  const replacement = await refreshed.json();
  expect((await mcp(replacement.access_token)).status).toBe(200);
  await Effect.runPromise(issuer.service.sql`DELETE FROM session`);
  const afterCleanup = await refresh(client_id, replacement.refresh_token);
  expect(afterCleanup.status, await afterCleanup.clone().text()).toBe(200);
  expect((await mcp((await afterCleanup.json()).access_token)).status).toBe(200);
});

// Mixed case also guards case-insensitive Basic scheme parsing.
test.each(["bAsIc", "private_key_jwt"])(
  "%s authentication without body client_id issues usable grants after revocation",
  async (method) => {
    const pair = method === "private_key_jwt" ? await generateKeyPair("ES256") : undefined;

    const registrationBody: PrivateKeyRegistration = {
      client_name: "Authenticated MCP client",
      redirect_uris: ["http://127.0.0.1:9876/callback"],
      token_endpoint_auth_method: method === "private_key_jwt" ? method : "client_secret_basic",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    };

    if (pair) {
      registrationBody.jwks = {
        keys: [{ ...(await exportJWK(pair.publicKey)), kid: "test-key" }],
      };
    }

    const registration = await handle(
      new Request(`${baseURL}/api/auth/oauth2/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(registrationBody),
      }),
    );

    expect(registration.status, await registration.clone().text()).toBe(201);
    const { client_id, client_secret } = await registration.json();

    const exchange = async (form: Record<string, string>) => {
      const body = new URLSearchParams(form);
      body.delete("client_id");
      const headers = new Headers({ "content-type": "application/x-www-form-urlencoded" });

      if (pair) {
        body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        body.set(
          "client_assertion",
          await new SignJWT({})
            .setProtectedHeader({ alg: "ES256", kid: "test-key" })
            .setIssuer(client_id)
            .setSubject(client_id)
            .setAudience(`${baseURL}/api/auth/oauth2/token`)
            .setIssuedAt()
            .setExpirationTime("2m")
            .setJti(randomUUID())
            .sign(pair.privateKey),
        );
      } else {
        headers.set(
          "authorization",
          `${method} ${Buffer.from(`${encodeURIComponent(client_id)}:${encodeURIComponent(client_secret)}`).toString("base64")}`,
        );
      }

      return handle(
        new Request(`${baseURL}/api/auth/oauth2/token`, { method: "POST", headers, body }),
      );
    };

    const first = await mcpOAuthGrant(handle, baseURL, cookie, { clientId: client_id, exchange });
    expect((await mcp(first.tokens.access_token)).status).toBe(200);
    expect((await admin("revokeClient", { client_id })).status).toBe(200);

    const revoked = await exchange({
      grant_type: "refresh_token",
      refresh_token: first.tokens.refresh_token,
      resource: `${baseURL}/mcp`,
    });

    expect(revoked.status).toBe(400);
    const renewed = await mcpOAuthGrant(handle, baseURL, cookie, { clientId: client_id, exchange });
    expect((await mcp(renewed.tokens.access_token)).status).toBe(200);

    const refreshed = await exchange({
      grant_type: "refresh_token",
      refresh_token: renewed.tokens.refresh_token,
      resource: `${baseURL}/mcp`,
    });

    expect(refreshed.status, await refreshed.clone().text()).toBe(200);
    expect((await mcp((await refreshed.json()).access_token)).status).toBe(200);
  },
);
