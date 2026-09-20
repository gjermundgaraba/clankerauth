import { Effect } from "effect";
import { afterEach, beforeEach, expect, test } from "vite-plus/test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { convertSetCookieToCookie } from "better-auth/test";
import { createOwner, initialize, openAuth, type Service } from "../src/auth.ts";
import { testSettings } from "./settings.ts";

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

let service: Service;

let directory: string;

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

  return service.auth.handler(new Request(`${baseURL}/api/auth${path}`, init));
}

function authorization(id: string, identifier = resource, port = 4184) {
  return (
    "/oauth2/authorize?" +
    new URLSearchParams({
      client_id: id,
      redirect_uri: `http://127.0.0.1:${port}/callback`,
      response_type: "code",
      scope: "openid offline_access resource:read",
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
  Effect.runPromise(service.sql`SELECT disabled FROM oauthClient WHERE clientId = ${id}`);

const consentRequired = async (id: string) =>
  (await request(authorization(id), undefined, true)).headers.get("location") ?? "";

const cimdTransport = async () => {
  fetches++;

  return Response.json(metadata, { headers: { "cache-control": metadataCacheControl } });
};

beforeEach(async () => {
  directory = mkdtempSync(join(tmpdir(), "clankerauth-clients-"));
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
  service = await Effect.runPromise(
    openAuth(testSettings({ baseURL, database: join(directory, "auth.sqlite") }), {
      cimdTransport,
    }),
  );
  await Effect.runPromise(initialize(service));
  await Effect.runPromise(
    createOwner(service, { email: "owner@example.com", password: "test-password-long-enough" }),
  );

  const login = await request("/sign-in/email", {
    email: "owner@example.com",
    password: "test-password-long-enough",
  });

  expect(login.status).toBe(200);
  cookie = convertSetCookieToCookie(login.headers).get("cookie") ?? "";
  await Effect.runPromise(
    service.resources.create(
      { identifier: resource, name: "Test resource", scopes: ["resource:read"] },
      ownerHeaders(),
    ),
  );
});

afterEach(async () => {
  await service.close();
  rmSync(directory, { recursive: true, force: true });
});

test("DCR infers native callbacks, keeps PKCE and consent, and revocation ends refresh", async () => {
  const client = await register();
  expect(client.application_type).toBe("native");
  const alternate = await request(authorization(client.client_id, resource, 4999), undefined, true);
  expect(alternate.headers.get("location")).toContain("/consent");
  const tokens = await grant(client.client_id);
  expect(tokens.access_token).toBeTypeOf("string");
  expect(await Effect.runPromise(service.clients.revoke(client.client_id))).toEqual({
    revoked: true,
  });
  expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
  expect(await consentRequired(client.client_id)).toContain("/consent");
});

test("DCR cannot self-assert consent bypass or unknown resources", async () => {
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
        resources: ["https://unconfigured.example/mcp"],
      })
    ).status,
  ).toBe(400);
});

test.each(["dcr", "cimd"])(
  "%s clients gain new resource eligibility and deletion revokes dependent grants",
  async (source) => {
    const client = source === "dcr" ? await register() : { client_id: clientId };

    if (source === "cimd") await request(authorization(clientId));
    const second = "https://second.example/mcp";
    await Effect.runPromise(
      service.resources.create(
        { identifier: second, name: "Second", scopes: ["second:read"] },
        ownerHeaders(),
      ),
    );
    expect(await Effect.runPromise(service.resources.hasAccess(client.client_id, second))).toBe(
      true,
    );
    const tokens = await grant(client.client_id);
    await Effect.runPromise(service.resources.delete(resource, ownerHeaders()));
    expect(await Effect.runPromise(service.resources.hasAccess(client.client_id, resource))).toBe(
      false,
    );
    expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
  },
);

test("the owner can narrow an automatic client's resource access", async () => {
  const client = await register();
  expect(await Effect.runPromise(service.resources.hasAccess(client.client_id, resource))).toBe(
    true,
  );
  await Effect.runPromise(service.resources.setAccess(client.client_id, [], ownerHeaders()));
  expect(await consentRequired(client.client_id)).not.toContain("/consent");
  await Effect.runPromise(
    service.resources.setAccess(client.client_id, [resource], ownerHeaders()),
  );
  expect(await consentRequired(client.client_id)).toContain("/consent");
});

test("blocking uses the provider's disabled flag and survives CIMD metadata rediscovery", async () => {
  expect(await consentRequired(clientId)).toContain("/consent");
  expect(fetches).toBe(1);
  const tokens = await grant(clientId);
  expect(await Effect.runPromise(service.clients.block(clientId, true))).toEqual({ blocked: true });
  expect(await blocked(clientId)).toEqual([{ disabled: 1 }]);
  expect((await refresh(clientId, tokens.refresh_token)).status).toBe(400);
  // Let the metadata cache expire so the next authorization rediscovers the document.
  await new Promise((resolve) => setTimeout(resolve, 1100));
  expect(await consentRequired(clientId)).not.toContain("/consent");
  expect(fetches).toBe(2);
  expect(await blocked(clientId)).toEqual([{ disabled: 1 }]);
  expect(await Effect.runPromise(service.clients.block(clientId, false))).toEqual({
    blocked: false,
  });
  expect(await consentRequired(clientId)).toContain("/consent");
});

test("blocking a dynamically registered client rejects authorization until unblocked", async () => {
  const client = await register();
  await Effect.runPromise(service.clients.block(client.client_id, true));
  const blocked = await request(authorization(client.client_id), undefined, true);
  expect(blocked.headers.get("location") ?? "").not.toContain("/consent");
  await Effect.runPromise(service.clients.block(client.client_id, false));
  expect(await consentRequired(client.client_id)).toContain("/consent");
});

test("block and revoke report unknown clients", async () => {
  await expect(Effect.runPromise(service.clients.revoke("missing"))).rejects.toThrow(
    "Client not found",
  );
  await expect(Effect.runPromise(service.clients.block("missing", true))).rejects.toThrow(
    "Client not found",
  );
});

test("initialization is repeatable and refresh grants survive a reopen", async () => {
  const client = await register();
  const tokens = await grant(client.client_id);
  const settings = service.settings;
  await service.close();
  service = await Effect.runPromise(openAuth(settings, { cimdTransport }));
  await Effect.runPromise(initialize(service));
  expect((await refresh(client.client_id, tokens.refresh_token)).status).toBe(200);
});

test("CIMD rejects malformed metadata before persisting a client", async () => {
  metadata = { client_id: clientId, redirect_uris: [callback], token_endpoint_auth_method: "none" };
  expect(await consentRequired(clientId)).not.toContain("/consent");
  expect(
    await Effect.runPromise(
      service.sql`SELECT clientId FROM oauthClient WHERE clientId = ${clientId}`,
    ),
  ).toEqual([]);
});
