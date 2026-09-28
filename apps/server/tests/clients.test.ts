import { Effect, Exit } from "effect";
import { BadRequest, NotFound } from "@clankerauth/admin-api";
import { afterEach, beforeEach, expect, test } from "vite-plus/test";
import { createHash } from "node:crypto";
import { convertSetCookieToCookie } from "better-auth/test";
import { createOwner } from "../src/auth.ts";
import { openIssuer, type Issuer } from "./issuer.ts";

const baseURL = "http://localhost:4183";

const resource = "https://resource.example/mcp";

const clientId = "https://client.example/oauth/metadata.json";

const callback = "http://127.0.0.1:4184/callback";

const verifier = "a".repeat(43);

type AuthRequestBody = { readonly [key: string]: string | boolean | null | readonly string[] };

type ClientMetadata = {
  client_id: string;
  client_name?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  grant_types?: string[];
  response_types?: string[];
};

let issuer: Issuer;

let cookie: string;

let fetches: number;

let metadata: ClientMetadata;

let metadataCacheControl: string;

const ownerHeaders = () => new Headers({ cookie, origin: baseURL });

async function request(path: string, body?: AuthRequestBody, authenticated = false) {
  const headers = new Headers({ "x-clankerauth-peer": "127.0.0.1" });

  if (body !== undefined)
    headers.set(
      "content-type",
      path === "/oauth2/token" ? "application/x-www-form-urlencoded" : "application/json",
    );

  if (authenticated) {
    headers.set("cookie", cookie);
    headers.set("origin", baseURL);
  }

  const init: RequestInit = {
    method: body !== undefined ? "POST" : "GET",
    headers,
  };

  if (body !== undefined) {
    init.body =
      path === "/oauth2/token"
        ? new URLSearchParams(
            Object.entries(body).map(([key, value]) => [key, String(value)]),
          ).toString()
        : JSON.stringify(body);
  }

  return issuer.service.auth.handler(new Request(`${baseURL}/api/auth${path}`, init));
}

function authorization(
  id: string,
  identifier = resource,
  port = 4184,
  scope = "offline_access resource:read",
) {
  return (
    "/oauth2/authorize?" +
    new URLSearchParams({
      client_id: id,
      redirect_uri: `http://127.0.0.1:${port}/callback`,
      response_type: "code",
      scope,
      resource: identifier,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      state: "clients-test",
    })
  );
}

async function register() {
  const response = await request("/oauth2/register", {
    client_name: "Dynamic client",
    redirect_uris: [callback],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });

  expect(response.status, await response.clone().text()).toBe(201);

  return response.json();
}

async function grant(id: string) {
  const response = await request(authorization(id), undefined, true);
  expect(response.status, await response.clone().text()).toBe(302);
  const location = new URL(response.headers.get("location")!, baseURL);
  expect(location.pathname).toBe("/consent");

  const consent = await request(
    "/oauth2/consent",
    { accept: true, oauth_query: location.search.slice(1) },
    true,
  );

  expect(consent.status, await consent.clone().text()).toBe(200);
  const code = new URL((await consent.json()).url).searchParams.get("code");

  const tokens = await request("/oauth2/token", {
    grant_type: "authorization_code",
    client_id: id,
    code,
    code_verifier: verifier,
    redirect_uri: callback,
    resource,
  });

  expect(tokens.status, await tokens.clone().text()).toBe(200);

  return tokens.json();
}

const refresh = (id: string, token: string) =>
  request("/oauth2/token", {
    grant_type: "refresh_token",
    client_id: id,
    refresh_token: token,
    resource,
  });

const blocked = (id: string) =>
  Effect.runPromise(issuer.service.sql`SELECT disabled FROM oauthClient WHERE clientId = ${id}`);

const consentRequired = async (id: string, identifier = resource, scope?: string) =>
  (await request(authorization(id, identifier, 4184, scope), undefined, true)).headers.get(
    "location",
  ) ?? "";

const second = "https://second.example/mcp";

const addSecond = () =>
  Effect.runPromise(
    issuer.service.resources.create(
      { identifier: second, name: "Second", scopes: ["second:read"] },
      ownerHeaders(),
    ),
  );

/** A first-party public client with access to the test resource, which skips consent. */
async function managed() {
  const client = await issuer.service.auth.api.adminCreateOAuthClient({
    headers: ownerHeaders(),
    body: {
      client_name: "Managed client",
      redirect_uris: [callback],
      application_type: "native",
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      scope: "offline_access resource:read",
      skip_consent: true,
    },
  });

  await Effect.runPromise(issuer.service.resources.setAccess(client.client_id, [resource]));

  return client.client_id;
}

const cimdTransport = async () => {
  fetches++;

  return Response.json(metadata, { headers: { "cache-control": metadataCacheControl } });
};

beforeEach(async () => {
  fetches = 0;
  metadataCacheControl = "max-age=1";
  metadata = {
    client_id: clientId,
    client_name: "Metadata client",
    redirect_uris: [callback],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
  issuer = await openIssuer({ baseURL }, { cimdTransport });
  await issuer.run(
    createOwner(issuer.service, {
      email: "owner@example.com",
      password: "test-password-long-enough",
    }),
  );

  const login = await request("/sign-in/email", {
    email: "owner@example.com",
    password: "test-password-long-enough",
  });

  expect(login.status).toBe(200);
  cookie = convertSetCookieToCookie(login.headers).get("cookie") ?? "";
  await Effect.runPromise(
    issuer.service.resources.create(
      { identifier: resource, name: "Test resource", scopes: ["resource:read"] },
      ownerHeaders(),
    ),
  );
});

afterEach(async () => {
  await issuer.close();
});

test("DCR infers native callbacks, keeps PKCE and consent, and revocation ends refresh", async () => {
  const client = await register();
  expect(client.application_type).toBe("native");
  const alternate = await request(authorization(client.client_id, resource, 4999), undefined, true);
  expect(alternate.headers.get("location")).toContain("/consent");
  const tokens = await grant(client.client_id);
  expect(tokens.access_token).toBeTypeOf("string");
  expect(await Effect.runPromise(issuer.service.clients.revoke(client.client_id))).toEqual({
    revoked: true,
  });
  expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
  expect(await consentRequired(client.client_id)).toContain("/consent");
});

test("DCR cannot self-assert consent bypass, and its resource list is ignored", async () => {
  expect(
    (
      await request("/oauth2/register", {
        client_name: "Untrusted",
        redirect_uris: [callback],
        token_endpoint_auth_method: "none",
        skip_consent: true,
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await request("/oauth2/register", {
        client_name: "Untrusted",
        redirect_uris: [callback],
        token_endpoint_auth_method: "none",
        resources: [resource, "https://unconfigured.example/mcp"],
      })
    ).status,
  ).toBe(201);
});

test.each(["dcr", "cimd"])(
  "%s clients may ask for resources added later, and deletion revokes dependent grants",
  async (source) => {
    const client = source === "dcr" ? await register() : { client_id: clientId };
    const tokens = await grant(client.client_id);
    await addSecond();
    expect(await consentRequired(client.client_id, second, "offline_access second:read")).toContain(
      "/consent",
    );
    await Effect.runPromise(issuer.service.resources.delete(resource, ownerHeaders()));
    expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
    expect(await consentRequired(client.client_id)).not.toContain("/consent");
  },
);

test("automatic clients have no configurable resource access", async () => {
  const client = await register();

  expect(
    await Effect.runPromise(Effect.flip(issuer.service.resources.setAccess(client.client_id, []))),
  ).toEqual(
    new BadRequest({
      error: "Automatic Clients may ask for any Resource; revoke or block them instead",
    }),
  );
  expect(await Effect.runPromise(issuer.service.resources.access())).toEqual([]);
});

test("blocking uses the provider's disabled flag and survives CIMD metadata rediscovery", async () => {
  expect(await consentRequired(clientId)).toContain("/consent");
  expect(fetches).toBe(1);
  const tokens = await grant(clientId);
  expect(await Effect.runPromise(issuer.service.clients.block(clientId, true))).toEqual({
    blocked: true,
  });
  expect(await blocked(clientId)).toEqual([{ disabled: 1 }]);
  expect((await refresh(clientId, tokens.refresh_token)).status).toBe(400);
  // Let the metadata cache expire so the next authorization rediscovers the document.
  await new Promise((resolve) => setTimeout(resolve, 1100));
  expect(await consentRequired(clientId)).not.toContain("/consent");
  expect(fetches).toBe(2);
  expect(await blocked(clientId)).toEqual([{ disabled: 1 }]);
  expect(await Effect.runPromise(issuer.service.clients.block(clientId, false))).toEqual({
    blocked: false,
  });
  expect(await consentRequired(clientId)).toContain("/consent");
});

test("blocking a dynamically registered client rejects authorization until unblocked", async () => {
  const client = await register();
  await Effect.runPromise(issuer.service.clients.block(client.client_id, true));
  const blocked = await request(authorization(client.client_id), undefined, true);
  expect(blocked.headers.get("location") ?? "").not.toContain("/consent");
  await Effect.runPromise(issuer.service.clients.block(client.client_id, false));
  expect(await consentRequired(client.client_id)).toContain("/consent");
});

test("block and revoke report unknown clients", async () => {
  const missing = new NotFound({ error: "Client not found" });
  expect(await Effect.runPromise(Effect.flip(issuer.service.clients.revoke("missing")))).toEqual(
    missing,
  );
  expect(
    await Effect.runPromise(Effect.flip(issuer.service.clients.block("missing", true))),
  ).toEqual(missing);
});

test("initialization is repeatable and refresh grants survive a reopen", async () => {
  const client = await register();
  const tokens = await grant(client.client_id);
  issuer = await issuer.reopen();
  expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(200);
});

test("CIMD rejects malformed metadata before persisting a client", async () => {
  metadata = { client_id: clientId, redirect_uris: [callback], token_endpoint_auth_method: "none" };
  expect(await consentRequired(clientId)).not.toContain("/consent");
  expect(
    await Effect.runPromise(
      issuer.service.sql`SELECT clientId FROM oauthClient WHERE clientId = ${clientId}`,
    ),
  ).toEqual([]);
});

test("revoking one resource leaves the client's other authorization", async () => {
  await addSecond();
  const client = await register();
  const tokens = await grant(client.client_id);

  const response = await request(
    authorization(client.client_id, second, 4184, "offline_access second:read"),
    undefined,
    true,
  );

  const location = new URL(response.headers.get("location")!, baseURL);

  const consent = await request(
    "/oauth2/consent",
    { accept: true, oauth_query: location.search.slice(1) },
    true,
  );

  expect(consent.status, await consent.clone().text()).toBe(200);
  const listed = await Effect.runPromise(issuer.service.clients.connections());
  expect(listed.map((connection) => [connection.resource, connection.scopes])).toEqual([
    [resource, ["resource:read"]],
    [second, ["second:read"]],
  ]);
  expect(listed[0]?.approvedAt).not.toBeNull();
  expect(listed[0]?.refreshedAt).not.toBeNull();
  // Approved but the code was never exchanged, so no refresh token exists.
  expect(listed[1]?.refreshedAt).toBeNull();

  await Effect.runPromise(issuer.service.clients.revoke(client.client_id, second));
  expect(
    (await Effect.runPromise(issuer.service.clients.connections())).map((c) => c.resource),
  ).toEqual([resource]);
  expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(200);
  expect(await consentRequired(client.client_id, second, "offline_access second:read")).toContain(
    "/consent",
  );
});

test("the owner can delete an automatic client, which may register again", async () => {
  const client = await register();
  const tokens = await grant(client.client_id);
  expect(await Effect.runPromise(issuer.service.clients.delete(client.client_id))).toEqual({
    deleted: true,
  });
  expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
  expect(await Effect.runPromise(issuer.service.clients.connections())).toEqual([]);
  expect(
    await Effect.runPromise(Effect.flip(issuer.service.clients.delete(client.client_id))),
  ).toEqual(new NotFound({ error: "Client not found" }));

  expect(await consentRequired(clientId)).toContain("/consent");
  await Effect.runPromise(issuer.service.clients.delete(clientId));
  expect(await consentRequired(clientId)).toContain("/consent");
});

test("a recreated resource does not revive authorization given for the deleted one", async () => {
  const client = await register();
  const tokens = await grant(client.client_id);
  await Effect.runPromise(issuer.service.resources.delete(resource, ownerHeaders()));
  await Effect.runPromise(
    issuer.service.resources.create(
      { identifier: resource, name: "Test resource", scopes: ["resource:read"] },
      ownerHeaders(),
    ),
  );
  expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
  expect(await consentRequired(client.client_id)).toContain("/consent");
});

test("creating a resource clears authorization a failed deletion left behind", async () => {
  const client = await register();
  const tokens = await grant(client.client_id);
  await Effect.runPromise(
    issuer.service
      .sql`CREATE TRIGGER fail_clear BEFORE DELETE ON oauthConsent BEGIN SELECT RAISE(ABORT, 'injected database failure'); END`,
  );
  expect(
    Exit.isFailure(
      await Effect.runPromiseExit(issuer.service.resources.delete(resource, ownerHeaders())),
    ),
  ).toBe(true);
  await Effect.runPromise(issuer.service.sql`DROP TRIGGER fail_clear`);
  expect(await Effect.runPromise(issuer.service.resources.get(resource))).toBeUndefined();

  await Effect.runPromise(
    issuer.service.resources.create(
      { identifier: resource, name: "Test resource", scopes: ["resource:read"] },
      ownerHeaders(),
    ),
  );
  expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
  expect(await consentRequired(client.client_id)).toContain("/consent");
});

test("the 0.10.0 upgrade runs once, clearing stored authorization and automatic clients' links", async () => {
  const client = await register();
  const tokens = await grant(client.client_id);
  // A link an earlier version gave an automatic client, on a database it last opened.
  await Effect.runPromise(
    issuer.service
      .sql`INSERT INTO oauthClientResource (id, clientId, resourceId, createdAt) VALUES ('earlier', ${client.client_id}, ${resource}, ${new Date().toISOString()})`,
  );
  const first = await managed();
  await Effect.runPromise(issuer.service.sql`PRAGMA user_version = 0`);
  issuer = await issuer.reopen();

  // Managed clients keep their access; only the automatic client's link goes.
  expect(await Effect.runPromise(issuer.service.resources.access())).toEqual([
    { client_id: first, resource },
  ]);

  expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
  expect(await Effect.runPromise(issuer.service.clients.connections())).toEqual([]);
  expect(await Effect.runPromise(issuer.service.sql`PRAGMA user_version`)).toEqual([
    { user_version: 1 },
  ]);
});

test("a managed client, which skips consent, shows a connection while it holds a refresh token", async () => {
  const id = await managed();
  expect(await Effect.runPromise(issuer.service.clients.connections())).toEqual([]);

  const response = await request(authorization(id), undefined, true);
  expect(response.status, await response.clone().text()).toBe(302);
  const code = new URL(response.headers.get("location")!).searchParams.get("code");
  expect(code).toBeTypeOf("string");

  const tokens = await request("/oauth2/token", {
    grant_type: "authorization_code",
    client_id: id,
    code: code!,
    code_verifier: verifier,
    redirect_uri: callback,
    resource,
  });

  expect(tokens.status, await tokens.clone().text()).toBe(200);
  const [connection, ...rest] = await Effect.runPromise(issuer.service.clients.connections());
  expect(rest).toEqual([]);
  expect(connection).toMatchObject({
    client_id: id,
    resource,
    scopes: ["resource:read"],
    approvedAt: null,
  });
  expect(connection?.refreshedAt).not.toBeNull();

  await Effect.runPromise(issuer.service.clients.revoke(id, resource));
  expect(await Effect.runPromise(issuer.service.clients.connections())).toEqual([]);
});
