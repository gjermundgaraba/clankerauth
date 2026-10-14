import { it } from "@effect/vitest";
import { expect, vi } from "vite-plus/test";
import { administrationTools, webMcpRequest, withMcpClient } from "./mcp.ts";
import { Context, Effect, Exit, Fiber, Layer, Schema, Scope } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import { InternalServerError } from "@clankerauth/admin-api";
import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { nodeHandler } from "../src/http/application.ts";
import { listen } from "../src/platform/node-http.ts";
import {
  issuerGeneration,
  testSettings,
  testWebApplication,
  WebApplication,
} from "./test-issuer.ts";
import {
  administrationResource,
  mcpOAuthGrant,
  oauthToken,
  type TestHandler,
} from "./mcp-oauth-helper.ts";
import { Database } from "../src/platform/sqlite.ts";
import { OwnerAccount } from "../src/owner/owner.ts";
import { Issuer } from "../src/issuer/issuer.ts";
import { Resources } from "../src/resources/resources.ts";

const baseURL = "http://localhost:3000";

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

class Dashboard extends Context.Service<
  Dashboard,
  { readonly handle: TestHandler; readonly cookie: string }
>()("mcp-oauth.test/Dashboard") {}

const signedIn = Layer.effect(
  Dashboard,
  Effect.gen(function* () {
    yield* (yield* OwnerAccount).create({
      email: "owner@example.internal",
      password: "test-only password123",
    });

    const handle = yield* WebApplication;

    const login = yield* Effect.promise(() =>
      handle(
        new Request(`${baseURL}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { origin: baseURL, "content-type": "application/json" },
          body: JSON.stringify({
            email: "owner@example.internal",
            password: "test-only password123",
          }),
        }),
      ),
    );

    expect(login.status).toBe(200);

    const cookie = login.headers
      .getSetCookie()
      .map((part) => part.split(";")[0])
      .join("; ");

    return { handle, cookie };
  }),
);

const dashboardIssuer = () => signedIn.pipe(Layer.provideMerge(testWebApplication({ baseURL })));

const send = (request: Request) =>
  Effect.flatMap(Dashboard, ({ handle }) => Effect.promise(() => handle(request)));

const json = (response: Response) => Effect.promise(() => response.json());

const text = (response: Response) => Effect.promise(() => response.clone().text());

const admin = (action: string, body: TestRequestBody) =>
  Effect.flatMap(Dashboard, ({ cookie }) =>
    send(
      new Request(`${baseURL}/api/${action}`, {
        method: "POST",
        headers: { cookie, origin: baseURL, "content-type": "application/json" },
        body: JSON.stringify(body),
      }),
    ),
  );

const mcp = (token?: string, headers: Record<string, string> = {}) =>
  send(
    webMcpRequest({
      method: "tools/list",
      url: `${baseURL}/mcp`,
      headers: token === undefined ? headers : { ...headers, authorization: `Bearer ${token}` },
    }),
  );

const refresh = (client_id: string, refresh_token: string) =>
  Effect.flatMap(Dashboard, ({ handle }) =>
    Effect.promise(() =>
      oauthToken(handle, baseURL, {
        grant_type: "refresh_token",
        client_id,
        refresh_token,
        resource: `${baseURL}/`,
      }),
    ),
  );

const grant = (options?: Parameters<typeof mcpOAuthGrant>[3]) =>
  Effect.flatMap(Dashboard, ({ handle, cookie }) =>
    Effect.promise(() => mcpOAuthGrant(handle, baseURL, cookie, options)),
  );

const neitherScope = Schema.encodeSync(Action.Forbidden)(
  new Action.Forbidden({ message: "Insufficient scope", scopes: ["clankerauth:read"] }),
);

it.live("anonymous discovery leads to PKCE owner consent, bearer administration, and refresh", () =>
  Effect.gen(function* () {
    const { handle } = yield* Dashboard;
    const unauthorized = yield* mcp();
    expect(unauthorized.status).toBe(401);
    const challenge = unauthorized.headers.get("www-authenticate");
    const metadataURL = /resource_metadata="([^"]+)"/.exec(challenge ?? "")?.[1];
    const metadata = yield* send(new Request(metadataURL ?? ""));
    expect(metadata.status).toBe(200);
    expect(yield* json(metadata)).toMatchObject({
      resource: `${baseURL}/`,
      authorization_servers: [`${baseURL}/api/auth`],
      scopes_supported: ["clankerauth:read", "clankerauth:write", "offline_access"],
    });

    const discovery = yield* send(
      new Request(`${baseURL}/.well-known/oauth-authorization-server/api/auth`),
    );

    expect(discovery.status).toBe(200);
    expect(yield* json(discovery)).toMatchObject({
      issuer: `${baseURL}/api/auth`,
      authorization_endpoint: `${baseURL}/api/auth/oauth2/authorize`,
      token_endpoint: `${baseURL}/api/auth/oauth2/token`,
      registration_endpoint: `${baseURL}/api/auth/oauth2/register`,
      code_challenge_methods_supported: ["S256"],
    });
    const { client_id, tokens } = yield* grant();
    expect((yield* mcp(tokens.access_token)).status).toBe(200);

    const http = yield* send(
      new Request(`${baseURL}/api/listClients`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${tokens.access_token}`,
          "content-type": "application/json",
        },
        body: "{}",
      }),
    );

    expect(http.status).toBe(401);
    yield* Effect.promise(() =>
      withMcpClient(
        {
          fetch: handle,
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
          expect(created.structuredContent).toMatchObject({ client_secret: expect.any(String) });
          const listing = await client.callTool({ name: "listClients", arguments: {} });
          expect(listing.isError).toBe(false);
          expect(JSON.stringify(listing.structuredContent)).not.toContain('"client_secret":');
        },
      ),
    );
    const rotated = yield* refresh(client_id, tokens.refresh_token);
    expect(rotated.status, yield* text(rotated)).toBe(200);
    const replacement = yield* json(rotated);
    expect(replacement.refresh_token).not.toBe(tokens.refresh_token);
    expect((yield* mcp(replacement.access_token)).status).toBe(200);
  }).pipe(Effect.provide(dashboardIssuer())),
);

it.live("an aborted MCP tool call settles its provider work and compensation before shutdown", () =>
  Effect.gen(function* () {
    const { tokens } = yield* grant();
    const { api } = (yield* Issuer).auth;
    const { sql } = yield* Database;
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
    vi.spyOn(yield* Resources, "link").mockReturnValue(
      Effect.fail(new InternalServerError({ message: "Request could not be completed" })),
    );
    vi.spyOn(api, "deleteOAuthClient").mockImplementation(async (context) => {
      const deleted = await deleteClient(context);
      compensated = true;

      return deleted;
    });

    // why: served as main.ts serves, so the server's scope owns its request fibers
    const scope = yield* Scope.fork(yield* Effect.scope, "sequential");
    const { port, serve } = yield* listen(0, "127.0.0.1").pipe(Scope.provide(scope));
    yield* serve(yield* nodeHandler().pipe(Scope.provide(scope))).pipe(Scope.provide(scope));

    yield* Effect.gen(function* () {
      const request = webMcpRequest({
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
      yield* Effect.promise(() => entered.promise);
      controller.abort();
      yield* Effect.promise(() => expect(call).rejects.toThrow());

      const stopping = yield* Effect.forkChild(
        Scope.close(scope, Exit.void).pipe(
          Effect.map(() => {
            stopped = true;

            return compensated;
          }),
        ),
      );

      // why: stateless MCP has no cancellation, so the aborted call still owns its write
      yield* Effect.sleep("50 millis");
      expect(stopped).toBe(false);
      release.resolve();
      expect(yield* Fiber.join(stopping)).toBe(true);
    }).pipe(
      Effect.ensuring(
        Effect.suspend(() => {
          release.resolve();

          return Scope.close(scope, Exit.void);
        }),
      ),
    );

    expect(
      yield* sql`SELECT clientId FROM oauthClient WHERE name = ${"Aborted through MCP"}`,
    ).toEqual([]);
  }).pipe(Effect.provide(dashboardIssuer())),
);

it.live(
  "MCP rejects cookies, API keys, malformed, expired, wrong-audience, and insufficient-scope tokens",
  () =>
    Effect.gen(function* () {
      const { cookie } = yield* Dashboard;

      const rejectedHeaders: Array<Record<string, string>> = [
        { cookie },
        { authorization: "Basic invalid" },
        { authorization: "Bearer invalid" },
      ];

      for (const headers of rejectedHeaders) {
        expect((yield* mcp(undefined, headers)).status).toBe(401);
      }

      const target = "https://resource.example/api";
      expect(
        (yield* admin("createResource", {
          identifier: target,
          name: "Other audience",
          scopes: ["read"],
        })).status,
      ).toBe(201);

      const created = yield* admin("createApiKey", {
        name: "Not an OAuth token",
        permissions: { [target]: ["read"] },
        expiresAt: null,
      });

      expect(created.status).toBe(201);
      expect((yield* mcp((yield* json(created)).key)).status).toBe(401);

      const other = yield* grant({
        resource: target,
        scope: "offline_access read",
      });

      expect((yield* mcp(other.tokens.access_token)).status).toBe(401);

      const insufficient = yield* grant({
        scope: "offline_access",
      });

      const denied = yield* mcp(insufficient.tokens.access_token);
      expect(denied.status).toBe(403);
      expect(yield* json(denied)).toEqual(neitherScope);
      const valid = yield* grant();
      const parts = valid.tokens.access_token.split(".");
      parts[1] = Buffer.from(
        JSON.stringify({
          sub: "not-owner",
          aud: `${baseURL}/`,
          scope: "clankerauth:read clankerauth:write",
        }),
      ).toString("base64url");
      expect((yield* mcp(parts.join("."))).status).toBe(401);
      yield* Effect.gen(function* () {
        vi.useFakeTimers({ toFake: ["Date"] });
        vi.setSystemTime(Date.now() + (Number(valid.tokens.expires_in) + 60) * 1000);
        expect((yield* mcp(valid.tokens.access_token)).status).toBe(401);
      }).pipe(Effect.ensuring(Effect.sync(() => vi.useRealTimers())));
    }).pipe(Effect.provide(dashboardIssuer())),
);

it.live("the administration resource is fixed, and every start restores it", () =>
  Effect.gen(function* () {
    const resource = administrationResource(baseURL);

    const cookie = yield* Effect.gen(function* () {
      expect((yield* admin("createResource", resource)).status).toBe(400);
      expect((yield* admin("updateResource", { ...resource, name: "Renamed" })).status).toBe(400);
      expect((yield* admin("deleteResource", { identifier: resource.identifier })).status).toBe(
        400,
      );
      yield* (yield* Database)
        .sql`UPDATE oauthResource SET name = 'Tampered', allowedScopes = ${JSON.stringify(["offline_access"])} WHERE identifier = ${resource.identifier}`;

      return (yield* Dashboard).cookie;
    }).pipe(
      Effect.provide(
        signedIn.pipe(
          Layer.provideMerge(WebApplication.layer),
          Layer.provideMerge(issuerGeneration()),
        ),
      ),
    );

    yield* Effect.gen(function* () {
      const handle = yield* WebApplication;

      const listing = yield* admin("listClients", {}).pipe(
        Effect.provideService(Dashboard, { handle, cookie }),
      );

      expect((yield* json(listing)).resources).toEqual([resource]);
    }).pipe(Effect.provide(WebApplication.layer.pipe(Layer.provideMerge(issuerGeneration()))));
  }).pipe(Effect.provide(testSettings({ baseURL }))),
);

it.live(
  "a read token may only list, a write token may do anything, and neither admits nothing",
  () =>
    Effect.gen(function* () {
      const { handle } = yield* Dashboard;

      const { client_id, tokens } = yield* grant({
        granted: "offline_access clankerauth:read",
      });

      expect(tokens.scope).toBe("offline_access clankerauth:read");

      const { connections } = yield* json(yield* admin("listClients", {}));
      expect(
        connections.find((connection: { client_id: string }) => connection.client_id === client_id)
          ?.scopes,
      ).toEqual(["clankerauth:read"]);

      yield* Effect.promise(() =>
        withMcpClient(
          {
            fetch: handle,
            path: "/mcp",
            baseUrl: baseURL,
            headers: { authorization: `Bearer ${tokens.access_token}` },
          },
          async (client) => {
            expect((await client.callTool({ name: "listClients", arguments: {} })).isError).toBe(
              false,
            );
            expect((await client.callTool({ name: "listApiKeys", arguments: {} })).isError).toBe(
              false,
            );
          },
        ),
      );

      const tools = yield* administrationTools(handle, baseURL, tokens.access_token);

      const escalation = yield* Effect.flip(
        tools.createApiKey({
          name: "Escalation",
          permissions: { "https://notes.example/": ["notes:read"] },
          expiresAt: null,
        }),
      );

      expect(escalation instanceof Action.Forbidden ? escalation.scopes : escalation).toEqual([
        "clankerauth:write",
      ]);

      expect((yield* json(yield* admin("listApiKeys", {}))).keys).toEqual([]);

      const writeOnly = yield* grant({
        scope: "offline_access clankerauth:write",
      });

      yield* Effect.promise(() =>
        withMcpClient(
          {
            fetch: handle,
            path: "/mcp",
            baseUrl: baseURL,
            headers: { authorization: `Bearer ${writeOnly.tokens.access_token}` },
          },
          async (client) => {
            expect((await client.callTool({ name: "listClients", arguments: {} })).isError).toBe(
              false,
            );

            const revoked = await client.callTool({
              name: "revokeClient",
              arguments: { client_id: writeOnly.client_id },
            });

            expect(revoked.isError).toBe(false);
          },
        ),
      );

      const neither = yield* grant({ scope: "offline_access" });
      const refused = yield* mcp(neither.tokens.access_token);

      expect(refused.status).toBe(403);
      expect(yield* json(refused)).toEqual(neitherScope);
    }).pipe(Effect.provide(dashboardIssuer())),
);

it.live.each(["block", "revoke"] as const)(
  "%s ends refresh at once; blocking also rejects live access tokens",
  (operation) =>
    Effect.gen(function* () {
      const { cookie } = yield* Dashboard;
      const { client_id, tokens } = yield* grant();
      expect((yield* mcp(tokens.access_token)).status).toBe(200);

      const payload: ClientActionPayload = { client_id };

      if (operation === "block") payload.blocked = true;

      const response = yield* admin(
        operation === "block" ? "blockClient" : "revokeClient",
        payload,
      );

      expect(response.status).toBe(200);
      const afterwards = yield* mcp(tokens.access_token);

      if (operation === "block") {
        expect(afterwards.status).toBe(401);

        const denied = yield* send(
          new Request(
            `${baseURL}/api/auth/oauth2/authorize?${new URLSearchParams({
              client_id,
              redirect_uri: "http://127.0.0.1:9876/callback",
              response_type: "code",
              resource: `${baseURL}/`,
              scope: "clankerauth:read clankerauth:write",
              code_challenge: "x".repeat(43),
              code_challenge_method: "S256",
              state: "blocked",
            })}`,
            { headers: { cookie } },
          ),
        );

        expect(denied.headers.get("location") ?? "").not.toContain("/consent");
      } else {
        // why: revocation clears stored grants; an issued access token lives until it expires
        expect(afterwards.status).toBe(200);
      }

      expect((yield* refresh(client_id, tokens.refresh_token)).status).toBe(400);

      if (operation === "block")
        expect((yield* admin("blockClient", { client_id, blocked: false })).status).toBe(200);

      const renewed = yield* grant({ clientId: client_id });
      expect((yield* mcp(renewed.tokens.access_token)).status).toBe(200);
    }).pipe(Effect.provide(dashboardIssuer())),
);

it.live("MCP protocol and owner-identity operations do not acquire provider sessions", () =>
  Effect.gen(function* () {
    const { handle } = yield* Dashboard;
    const resource = "https://automation.example/api";
    expect(
      (yield* admin("createResource", {
        identifier: resource,
        name: "Automation",
        scopes: ["read"],
      })).status,
    ).toBe(201);
    const { tokens } = yield* grant();
    const target = yield* grant();
    const { context } = yield* Issuer;
    const createSession = vi.spyOn(context.internalAdapter, "createSession");
    const deleteSession = vi.spyOn(context.internalAdapter, "deleteSession");
    yield* Effect.promise(() =>
      withMcpClient(
        {
          fetch: handle,
          path: "/mcp",
          baseUrl: baseURL,
          headers: { authorization: `Bearer ${tokens.access_token}` },
        },
        async (client) => {
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

          const key = Schema.decodeUnknownSync(Schema.Struct({ keyId: Schema.String }))(
            created.structuredContent,
          );

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
      ),
    );
  }).pipe(Effect.provide(dashboardIssuer())),
);

it.live(
  "provider-backed MCP writes release temporary sessions and offline grants survive owner sign-out",
  () =>
    Effect.gen(function* () {
      const { handle, cookie } = yield* Dashboard;
      const { client_id, tokens } = yield* grant();
      const services = yield* Effect.context<Database>();

      const sessions = Effect.flatMap(
        Database,
        ({ sql }) => sql`SELECT id FROM session ORDER BY id`,
      );

      const before = yield* sessions;
      const { context } = yield* Issuer;
      const createSession = vi.spyOn(context.internalAdapter, "createSession");
      const deleteSession = vi.spyOn(context.internalAdapter, "deleteSession");
      yield* Effect.promise(() =>
        withMcpClient(
          {
            fetch: handle,
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
        ),
      );
      // why: a response may resolve before its request Scope finishes releasing
      yield* Effect.promise(() =>
        expect.poll(() => Effect.runPromiseWith(services)(sessions)).toEqual(before),
      );
      expect(createSession).toHaveBeenCalledTimes(2);
      expect(deleteSession).toHaveBeenCalledTimes(2);

      const logout = yield* send(
        new Request(`${baseURL}/api/auth/sign-out`, {
          method: "POST",
          headers: { cookie, origin: baseURL, "content-type": "application/json" },
          body: "{}",
        }),
      );

      expect(logout.status).toBe(200);
      expect((yield* mcp(tokens.access_token)).status).toBe(200);
      const refreshed = yield* refresh(client_id, tokens.refresh_token);
      expect(refreshed.status, yield* text(refreshed)).toBe(200);
      expect((yield* mcp((yield* json(refreshed)).access_token)).status).toBe(200);
    }).pipe(Effect.provide(dashboardIssuer())),
);

it.live("deleting a client ends MCP access and refresh", () =>
  Effect.gen(function* () {
    const { sql } = yield* Database;
    const { client_id, tokens } = yield* grant();
    expect((yield* mcp(tokens.access_token)).status).toBe(200);
    yield* sql`DELETE FROM oauthClientResource WHERE clientId = ${client_id}`;
    yield* sql`DELETE FROM oauthClient WHERE clientId = ${client_id}`;
    expect((yield* mcp(tokens.access_token)).status).toBe(401);
    expect((yield* refresh(client_id, tokens.refresh_token)).status).toBe(400);
  }).pipe(Effect.provide(dashboardIssuer())),
);

it.live("offline MCP access and refresh survive browser-session expiry and cleanup", () =>
  Effect.gen(function* () {
    const { sql } = yield* Database;
    const { client_id, tokens } = yield* grant();
    expect((yield* mcp(tokens.access_token)).status).toBe(200);
    yield* sql`UPDATE session SET expiresAt = ${new Date(Date.now() - 60_000).toISOString()}`;
    expect((yield* mcp(tokens.access_token)).status).toBe(200);
    const refreshed = yield* refresh(client_id, tokens.refresh_token);
    expect(refreshed.status, yield* text(refreshed)).toBe(200);
    const replacement = yield* json(refreshed);
    expect((yield* mcp(replacement.access_token)).status).toBe(200);
    yield* sql`DELETE FROM session`;
    const afterCleanup = yield* refresh(client_id, replacement.refresh_token);
    expect(afterCleanup.status, yield* text(afterCleanup)).toBe(200);
    expect((yield* mcp((yield* json(afterCleanup)).access_token)).status).toBe(200);
  }).pipe(Effect.provide(dashboardIssuer())),
);

// why: mixed case also checks that the Basic scheme is matched case-insensitively
it.live.each(["bAsIc", "private_key_jwt"])(
  "%s authentication without body client_id issues usable grants after revocation",
  (method) =>
    Effect.gen(function* () {
      const { handle } = yield* Dashboard;

      const pair =
        method === "private_key_jwt"
          ? yield* Effect.promise(() => generateKeyPair("ES256"))
          : undefined;

      const registrationBody: PrivateKeyRegistration = {
        client_name: "Authenticated MCP client",
        redirect_uris: ["http://127.0.0.1:9876/callback"],
        token_endpoint_auth_method: method === "private_key_jwt" ? method : "client_secret_basic",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      };

      if (pair) {
        registrationBody.jwks = {
          keys: [{ ...(yield* Effect.promise(() => exportJWK(pair.publicKey))), kid: "test-key" }],
        };
      }

      const registration = yield* send(
        new Request(`${baseURL}/api/auth/oauth2/register`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(registrationBody),
        }),
      );

      expect(registration.status, yield* text(registration)).toBe(201);
      const { client_id, client_secret } = yield* json(registration);

      const exchange = async (form: Record<string, string>) => {
        const body = new URLSearchParams(form);
        body.delete("client_id");
        const headers = new Headers({ "content-type": "application/x-www-form-urlencoded" });

        if (pair) {
          body.set(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          );
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

      const first = yield* grant({ clientId: client_id, exchange });
      expect((yield* mcp(first.tokens.access_token)).status).toBe(200);
      expect((yield* admin("revokeClient", { client_id })).status).toBe(200);

      const revoked = yield* Effect.promise(() =>
        exchange({
          grant_type: "refresh_token",
          refresh_token: first.tokens.refresh_token,
          resource: `${baseURL}/`,
        }),
      );

      expect(revoked.status).toBe(400);
      const renewed = yield* grant({ clientId: client_id, exchange });
      expect((yield* mcp(renewed.tokens.access_token)).status).toBe(200);

      const refreshed = yield* Effect.promise(() =>
        exchange({
          grant_type: "refresh_token",
          refresh_token: renewed.tokens.refresh_token,
          resource: `${baseURL}/`,
        }),
      );

      expect(refreshed.status, yield* text(refreshed)).toBe(200);
      expect((yield* mcp((yield* json(refreshed)).access_token)).status).toBe(200);
    }).pipe(Effect.provide(dashboardIssuer())),
);

it.live("an access token administers over HTTP at /api/owner, as it does over MCP", () =>
  Effect.gen(function* () {
    const { cookie } = yield* Dashboard;

    const owner = (action: string, body: TestRequestBody, headers: Record<string, string> = {}) =>
      send(
        new Request(`${baseURL}/api/owner/${action}`, {
          method: "POST",
          headers: { ...headers, "content-type": "application/json" },
          body: JSON.stringify(body),
        }),
      );

    const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

    const anonymous = yield* owner("listApiKeys", {});
    expect(anonymous.status).toBe(401);
    expect(anonymous.headers.get("www-authenticate")).toContain(
      `resource_metadata="${baseURL}/.well-known/oauth-protected-resource"`,
    );
    expect((yield* owner("listApiKeys", {}, { cookie, origin: baseURL })).status).toBe(401);

    const resource = {
      identifier: "https://notes.internal/",
      name: "Notes",
      scopes: ["notes:read"],
    };

    expect((yield* admin("createResource", resource)).status).toBe(201);

    const { tokens } = yield* grant();

    const created = yield* owner(
      "createApiKey",
      { name: "cli", permissions: { [resource.identifier]: ["notes:read"] }, expiresAt: null },
      bearer(tokens.access_token),
    );

    expect(created.status, yield* text(created)).toBe(201);
    const key = yield* json(created);
    expect(key.key).toBeTypeOf("string");

    const listed = yield* owner("listApiKeys", {}, bearer(tokens.access_token));
    expect(listed.status).toBe(200);
    expect((yield* json(listed)).keys.map((entry: { keyId: string }) => entry.keyId)).toEqual([
      key.keyId,
    ]);

    const reader = yield* grant({
      scope: "offline_access clankerauth:read",
    });

    expect((yield* owner("listApiKeys", {}, bearer(reader.tokens.access_token))).status).toBe(200);
    expect(
      (yield* owner("deleteApiKey", { keyId: key.keyId }, bearer(reader.tokens.access_token)))
        .status,
    ).toBe(403);

    expect(
      (yield* owner("keyList", { resource: resource.identifier }, bearer(tokens.access_token)))
        .status,
    ).toBe(404);
  }).pipe(Effect.provide(dashboardIssuer())),
);
