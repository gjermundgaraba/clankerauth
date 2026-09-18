import { Effect } from "effect";
import { afterEach, beforeEach, expect, test } from "vite-plus/test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createOwner, initialize, openAuth, type Service } from "../src/auth.ts";

const baseURL = "http://localhost:4183";

const resource = "https://resource.example/mcp";

const clientId = "https://client.example/oauth/metadata.json";

const callback = "http://127.0.0.1:4184/callback";

const verifier = "a".repeat(43);

type AuthRequestValue = string | boolean | null | readonly string[];

type AuthRequestBody = { readonly [key: string]: AuthRequestValue };

type AuthRequestHeaders = {
  "x-clankerauth-peer": string;
  "content-type"?: string;
  cookie?: string;
  origin?: string;
};

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

async function request(path: string, body?: AuthRequestBody, authenticated = false) {
  const headers: AuthRequestHeaders = {
    "x-clankerauth-peer": "127.0.0.1",
  };

  if (body !== undefined) {
    headers["content-type"] =
      path === "/oauth2/token" ? "application/x-www-form-urlencoded" : "application/json";
  }

  if (authenticated) {
    headers.cookie = cookie;
    headers.origin = baseURL;
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

  const response = await service.auth.handler(new Request(`${baseURL}/api/auth${path}`, init));

  return response;
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
      state: "onboarding-test",
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

const cimdTransport = async () => {
  fetches++;

  return Response.json(metadata, { headers: { "cache-control": metadataCacheControl } });
};

beforeEach(async () => {
  directory = mkdtempSync(join(tmpdir(), "clankerauth-onboarding-"));
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
  service = await openAuth(
    {
      baseURL,
      database: join(directory, "auth.sqlite"),
      secret: "test-secret-with-more-than-thirty-two-characters",
      host: "127.0.0.1",
      port: 4183,
    },
    {
      cimdTransport,
    },
  );
  await initialize(service);
  await createOwner(service, { email: "owner@example.com", password: "test-password-long-enough" });

  const login = await request("/sign-in/email", {
    email: "owner@example.com",
    password: "test-password-long-enough",
  });

  expect(login.status).toBe(200);
  cookie = login.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
  await Effect.runPromise(
    service.resources.create(
      {
        identifier: resource,
        name: "Test resource",
        scopes: ["resource:read"],
      },
      new Headers({ cookie, origin: baseURL }),
    ),
  );
});

afterEach(async () => {
  await service.close();
  rmSync(directory, { recursive: true, force: true });
});

test("DCR infers native callbacks, preserves PKCE and consent, and issues revocable resource grants", async () => {
  const client = await register();
  expect(client.application_type).toBe("native");
  expect(await Effect.runPromise(service.onboarding.list())).toEqual([
    { client_id: client.client_id, onboarding: "dcr", blocked: false },
  ]);
  const alternate = await request(authorization(client.client_id, resource, 4999), undefined, true);
  expect(alternate.headers.get("location")).toContain("/consent");
  const tokens = await grant(client.client_id);
  expect(tokens.access_token).toBeTypeOf("string");
  await Effect.runPromise(service.onboarding.revoke(client.client_id));

  const refresh = await request("/oauth2/token", {
    grant_type: "refresh_token",
    client_id: client.client_id,
    refresh_token: tokens.refresh_token,
    resource,
  });

  expect(refresh.status).toBe(400);
  expect(
    (await request(authorization(client.client_id), undefined, true)).headers.get("location"),
  ).toContain("/consent");
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
        new Headers({ cookie, origin: baseURL }),
      ),
    );
    expect(await Effect.runPromise(service.resources.hasAccess(client.client_id, second))).toBe(
      true,
    );
    const tokens = await grant(client.client_id);
    await Effect.runPromise(
      service.resources.delete(resource, new Headers({ cookie, origin: baseURL })),
    );
    expect(await Effect.runPromise(service.resources.hasAccess(client.client_id, resource))).toBe(
      false,
    );

    const refresh = await request("/oauth2/token", {
      grant_type: "refresh_token",
      client_id: client.client_id,
      refresh_token: tokens.refresh_token,
      resource,
    });

    expect(refresh.status).toBe(400);
  },
);

test("CIMD provenance is transactional and blocking survives provider metadata deletion", async () => {
  const response = await request(authorization(clientId), undefined, true);
  expect(response.headers.get("location"), await response.clone().text()).toContain("/consent");
  expect(fetches).toBe(1);
  expect(await Effect.runPromise(service.onboarding.list())).toEqual([
    { client_id: clientId, onboarding: "cimd", blocked: false },
  ]);
  await Effect.runPromise(service.onboarding.block(clientId, true));
  await Effect.runPromise(
    service.sql`DELETE FROM oauthClientResource WHERE clientId = ${clientId}`,
  );
  await Effect.runPromise(service.sql`DELETE FROM oauthClient WHERE clientId = ${clientId}`);
  const blocked = await request(authorization(clientId), undefined, true);
  expect(blocked.headers.get("location") ?? "").not.toContain("/consent");
  expect(fetches).toBe(1);
  expect((await Effect.runPromise(service.onboarding.list()))[0]?.blocked).toBe(true);
});

test("DCR blocking survives provider client deletion", async () => {
  const { client_id: clientId } = await register();
  await Effect.runPromise(service.onboarding.block(clientId, true));
  await Effect.runPromise(
    service.sql`DELETE FROM oauthClientResource WHERE clientId = ${clientId}`,
  );
  await Effect.runPromise(service.sql`DELETE FROM oauthClient WHERE clientId = ${clientId}`);
  const blocked = await request(authorization(clientId), undefined, true);
  expect(blocked.status).toBe(400);
  expect(await blocked.json()).toMatchObject({ error: "invalid_client" });
  expect(await Effect.runPromise(service.onboarding.list())).toEqual([
    { client_id: clientId, onboarding: "dcr", blocked: true },
  ]);
});

test("initialization preserves DCR and CIMD clients, policy, and grants", async () => {
  const current = await register();
  const currentTokens = await grant(current.client_id);
  const metadataTokens = await grant(clientId);

  const snapshot = () =>
    Effect.runPromise(
      Effect.all({
        clients: service.sql`SELECT * FROM oauthClient ORDER BY clientId`,
        policy: service.sql`SELECT * FROM clientOnboarding ORDER BY clientId`,
        consents: service.sql`SELECT * FROM oauthConsent ORDER BY id`,
        refreshTokens: service.sql`SELECT * FROM oauthRefreshToken ORDER BY id`,
      }),
    );

  const before = await snapshot();
  const settings = service.settings;
  await service.close();
  service = await openAuth(settings, { cimdTransport });
  await initialize(service);
  expect(await snapshot()).toEqual(before);

  const refresh = await request("/oauth2/token", {
    grant_type: "refresh_token",
    client_id: current.client_id,
    refresh_token: currentTokens.refresh_token,
    resource,
  });

  expect(refresh.status, await refresh.clone().text()).toBe(200);

  const metadataRefresh = await request("/oauth2/token", {
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: metadataTokens.refresh_token,
    resource,
  });

  expect(metadataRefresh.status, await metadataRefresh.clone().text()).toBe(200);
  await Effect.runPromise(service.onboarding.block(clientId, true));
  expect(await Effect.runPromise(service.onboarding.list())).toContainEqual({
    client_id: clientId,
    onboarding: "cimd",
    blocked: true,
  });
});

test("abandoned registrations are removed but consented and blocked clients remain", async () => {
  const stale = await register();
  const approved = await register();
  const blocked = await register();
  await grant(approved.client_id);
  await Effect.runPromise(service.onboarding.block(blocked.client_id, true));
  await Effect.runPromise(service.sql`UPDATE oauthClient SET createdAt = 0`);
  await Effect.runPromise(service.onboarding.cleanup());
  const clients = await Effect.runPromise(service.onboarding.list());
  expect(
    clients.map((client) => client.client_id).toSorted((left, right) => left.localeCompare(right)),
  ).toEqual(
    [approved.client_id, blocked.client_id].toSorted((left, right) => left.localeCompare(right)),
  );
  expect(await Effect.runPromise(service.resources.hasAccess(stale.client_id, resource))).toBe(
    false,
  );
});

test("CIMD metadata change during refresh revokes the in-flight grant as well as stored consent", async () => {
  const tokens = await grant(clientId);
  metadata = { ...metadata, redirect_uris: [callback, "http://127.0.0.1:4184/other"] };
  // Respect the plugin's per-client network pacing while expiring its cache.
  await new Promise((resolve) => setTimeout(resolve, 1100));

  const refresh = await request("/oauth2/token", {
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: tokens.refresh_token,
    resource,
  });

  expect(refresh.status, await refresh.clone().text()).toBe(400);
  expect(
    await Effect.runPromise(service.sql`SELECT id FROM oauthConsent WHERE clientId = ${clientId}`),
  ).toEqual([]);
  expect(
    await Effect.runPromise(
      service.sql`SELECT id FROM oauthRefreshToken WHERE clientId = ${clientId}`,
    ),
  ).toEqual([]);
});

test("CIMD rejects malformed metadata before persisting a client", async () => {
  metadata = { client_id: clientId, redirect_uris: [callback], token_endpoint_auth_method: "none" };
  const response = await request(authorization(clientId), undefined, true);
  expect(response.headers.get("location") ?? "").not.toContain("/consent");
  expect(await Effect.runPromise(service.onboarding.list())).toEqual([]);
});

test("DCR registration capacity rejects new clients while retaining blocked identities", async () => {
  await Effect.runPromise(
    service.sql`WITH RECURSIVE n(value) AS (VALUES(1) UNION ALL SELECT value + 1 FROM n WHERE value < 1000) INSERT INTO clientOnboarding (clientId, source, blocked) SELECT 'blocked-' || value, 'dcr', 1 FROM n`,
  );

  const response = await request("/oauth2/register", {
    client_name: "Over capacity",
    redirect_uris: [callback],
    token_endpoint_auth_method: "none",
  });

  expect(response.status).toBe(429);
  expect((await Effect.runPromise(service.onboarding.list())).length).toBe(1000);
});

test("DCR rate limiting permits ten registrations per peer per minute", async () => {
  for (let index = 0; index < 10; index++) await register();

  const response = await request("/oauth2/register", {
    client_name: "Too frequent",
    redirect_uris: [callback],
    token_endpoint_auth_method: "none",
  });

  expect(response.status).toBe(429);
});

test("expired pending codes do not retain abandoned registrations", async () => {
  const stale = await register();
  const pending = await register();
  await Effect.runPromise(service.sql`UPDATE oauthClient SET createdAt = 0`);

  for (const [id, expiresAt] of [
    [stale.client_id, Date.now() - 1000],
    [pending.client_id, Date.now() + 60000],
  ]) {
    const value = JSON.stringify({
      type: "authorization_code",
      query: { client_id: id },
      referenceId: `resource:${resource}`,
    });

    await Effect.runPromise(
      service.sql`INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (${String(id)}, ${String(id)}, ${value}, ${Number(expiresAt)}, 0, 0)`,
    );
  }

  await Effect.runPromise(service.onboarding.cleanup());
  expect(
    (await Effect.runPromise(service.onboarding.list())).map((client) => client.client_id),
  ).toEqual([pending.client_id]);
});

test("CIMD discovery reclaims abandoned clients at capacity without DCR activity", async () => {
  await Effect.runPromise(
    service.sql`WITH RECURSIVE n(value) AS (VALUES(1) UNION ALL SELECT value + 1 FROM n WHERE value < 1000)
      INSERT INTO oauthClient (id, clientId, clientDiscoveryId, redirectUris, createdAt, updatedAt)
      SELECT 'stale-' || value, 'https://stale.example/' || value, 'cimd', '[]', 0, 0 FROM n`,
  );
  expect((await Effect.runPromise(service.onboarding.list())).length).toBe(1000);
  expect((await request(authorization(clientId))).status).toBe(302);
  expect(await Effect.runPromise(service.onboarding.list())).toEqual([
    { client_id: clientId, onboarding: "cimd", blocked: false },
  ]);
  expect(await Effect.runPromise(service.sql`SELECT clientId FROM oauthClient`)).toEqual([
    { clientId },
  ]);
});

test("cached CIMD recreation cannot exceed capacity after abandoned-client cleanup", async () => {
  metadataCacheControl = "max-age=300";
  expect((await request(authorization(clientId))).status).toBe(302);
  await Effect.runPromise(
    service.sql`UPDATE oauthClient SET createdAt = 0 WHERE clientId = ${clientId}`,
  );
  expect(await Effect.runPromise(service.onboarding.admit())).toBe(true);
  expect(await Effect.runPromise(service.onboarding.list())).toEqual([]);
  await Effect.runPromise(
    service.sql`WITH RECURSIVE n(value) AS (VALUES(1) UNION ALL SELECT value + 1 FROM n WHERE value < 1000) INSERT INTO clientOnboarding (clientId, source, blocked) SELECT 'blocked-' || value, 'dcr', 1 FROM n`,
  );
  const response = await request(authorization(clientId));
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(fetches).toBe(1);
  expect((await Effect.runPromise(service.onboarding.list())).length).toBe(1000);
  expect(
    await Effect.runPromise(
      service.sql`SELECT clientId FROM oauthClient WHERE clientId = ${clientId}`,
    ),
  ).toEqual([]);
});

test.each([false, true])(
  "DCR provenance commits atomically (session=%s)",
  async (authenticated) => {
    const body = {
      client_name: "Atomic registration",
      redirect_uris: [callback],
      token_endpoint_auth_method: "none",
    };

    const response = await request("/oauth2/register", body, authenticated);
    expect(response.status, await response.clone().text()).toBe(201);
    const client = await response.json();
    expect(await Effect.runPromise(service.onboarding.list())).toEqual([
      { client_id: client.client_id, onboarding: "dcr", blocked: false },
    ]);

    const stored = await Effect.runPromise(
      service.sql`SELECT userId, referenceId FROM oauthClient WHERE clientId = ${client.client_id}`,
    );

    expect(stored[0]).toMatchObject({
      userId: null,
      referenceId: authenticated ? "clankerauth:dcr" : null,
    });

    await Effect.runPromise(
      service.sql`CREATE TRIGGER rejectDcrTracking BEFORE INSERT ON clientOnboarding WHEN NEW.source = 'dcr' BEGIN SELECT RAISE(ABORT, 'Injected tracking failure'); END`,
    );
    const failed = await request("/oauth2/register", body, authenticated);
    expect(failed.status).toBe(500);
    expect(await Effect.runPromise(service.sql`SELECT clientId FROM oauthClient`)).toEqual([
      { clientId: client.client_id },
    ]);
    expect(await Effect.runPromise(service.resources.access())).toEqual([
      { client_id: client.client_id, resource: `${baseURL}/mcp` },
      { client_id: client.client_id, resource },
    ]);
    expect((await Effect.runPromise(service.onboarding.list())).length).toBe(1);
  },
);

test("abandoned client rows and their generations are removed across repeated cleanup cycles", async () => {
  for (let cycle = 0; cycle < 2; cycle++) {
    await Effect.runPromise(service.sql`WITH RECURSIVE n(value) AS (VALUES(1) UNION ALL SELECT value + 1 FROM n WHERE value < 2)
      INSERT INTO oauthClient (id, clientId, redirectUris, createdAt, updatedAt)
      SELECT ${String(cycle)} || '-' || value, ${String(cycle)} || '-' || value, '[]', 0, 0 FROM n`);
    expect(
      await Effect.runPromise(
        service.sql`SELECT count(*) AS count FROM oauthClient WHERE length(grantGeneration) = 32`,
      ),
    ).toEqual([{ count: 2 }]);
    await Effect.runPromise(service.onboarding.cleanup());
    expect(await Effect.runPromise(service.sql`SELECT count(*) AS count FROM oauthClient`)).toEqual(
      [{ count: 0 }],
    );
    expect(await Effect.runPromise(service.onboarding.list())).toEqual([]);
  }
});
