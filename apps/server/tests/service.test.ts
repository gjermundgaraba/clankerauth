import { Effect, Schema } from "effect";
import { BadRequest, InternalServerError } from "@clankerauth/admin-api";
import { sql as query } from "kysely";
import { afterEach, beforeEach, describe, expect, test, vi } from "vite-plus/test";
import { createHash, randomBytes } from "node:crypto";
import { createLocalJWKSet, jwtVerify } from "jose";
import { webApplication as application } from "./web-application.ts";
import { openIssuer, type Issuer } from "./issuer.ts";

import { administrationResource } from "./mcp-oauth-helper.ts";

const FormFields = Schema.Record(Schema.String, Schema.String);

type JsonPrimitive = string | number | boolean | null;

type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };

type TestRequestBody = { readonly [key: string]: JsonValue };

const password = "test-only owner password 8rS!";

const email = "owner@example.internal";

const resourceA = "https://notes.internal/mcp";

const resourceB = "https://reports.internal/api";

let issuer: Issuer;

let service: Issuer["service"];

let handle: ReturnType<typeof application>;

let applications: ReturnType<typeof application>[];

function createApplication() {
  const app = application(service);
  applications.push(app);

  return app;
}

async function stopCurrentGeneration() {
  const results = await Promise.allSettled(
    applications.splice(0).map(async (app) => app.dispose()),
  );

  const failures = results.flatMap((result) =>
    result.status === "rejected" ? [result.reason] : [],
  );

  try {
    await issuer.stop();
  } catch (error) {
    failures.push(error);
  }

  if (failures.length) throw new AggregateError(failures, "Failed to stop service generation");
}

let settings: Issuer["settings"];

let cookies: Map<string, string>;

async function request(
  path: string,
  body?: TestRequestBody,
  options: { anonymous?: boolean; form?: boolean; origin?: string; authorization?: string } = {},
) {
  const headers = new Headers({
    origin: options.origin ?? settings.baseURL,
    "x-clankerauth-peer": "127.0.0.1",
  });

  if (options.authorization) headers.set("authorization", options.authorization);

  if (!options.anonymous)
    headers.set("cookie", [...cookies].map(([k, v]) => `${k}=${v}`).join("; "));

  if (body)
    headers.set(
      "content-type",
      options.form ? "application/x-www-form-urlencoded" : "application/json",
    );

  let encoded: string | undefined;

  if (body !== undefined) {
    if (options.form) {
      encoded = new URLSearchParams(Schema.decodeUnknownSync(FormFields)(body)).toString();
    } else {
      encoded = JSON.stringify(body);
    }
  }

  const response = await handle(
    new Request(new URL(path, settings.baseURL), {
      method: body ? "POST" : "GET",
      headers,
      body: encoded,
    }),
  );

  if (!options.anonymous)
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      cookies.set(pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1));
    }

  return response;
}

async function login(pass = password) {
  return request("/api/auth/sign-in/email", { email, password: pass });
}

const resourceFixtures = [
  { identifier: resourceA, name: "Notes MCP", scopes: ["notes:read", "notes:write"] },
  { identifier: resourceB, name: "Reports", scopes: ["reports:read"] },
];

async function createResourceFixtures() {
  const listing = await (await request("/api/administration/listClients", {})).json();

  for (const resource of resourceFixtures) {
    if (
      listing.resources.some(
        (row: { identifier: string }) => row.identifier === resource.identifier,
      )
    )
      continue;
    const response = await request("/api/administration/createResource", resource);
    expect(response.status, await response.clone().text()).toBe(201);
  }
}

async function client(resource = resourceA, confidential = false) {
  await createResourceFixtures();

  const response = await request("/api/administration/createClient", {
    client_name: "Test application",
    redirect_uris: ["http://127.0.0.1:9876/callback"],
    resources: [resource],
    application_type: "native",
    token_endpoint_auth_method: confidential ? "client_secret_basic" : "none",
  });

  expect(response.status, await response.clone().text()).toBe(201);

  return response.json();
}

async function dynamicClient() {
  await createResourceFixtures();

  const response = await request(
    "/api/auth/oauth2/register",
    {
      client_name: "Dynamic client",
      redirect_uris: ["http://127.0.0.1:9876/callback"],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    },
    { anonymous: true },
  );

  expect(response.status, await response.clone().text()).toBe(201);

  return response.json();
}

/** An authorization request without a prompt parameter: the server decides about consent. */
function unprompted(clientId: string, resource = resourceA, extra: Record<string, string> = {}) {
  const flow = authorization(clientId, resource, extra);
  const url = new URL(flow.path, settings.baseURL);
  url.searchParams.delete("prompt");

  return { verifier: flow.verifier, path: `${url.pathname}${url.search}` };
}

function authorization(clientId: string, resource = resourceA, extra: Record<string, string> = {}) {
  const verifier = randomBytes(32).toString("base64url");

  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: "http://127.0.0.1:9876/callback",
    response_type: "code",
    scope: "offline_access notes:read",
    resource,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state: "state-to-validate",
    prompt: "consent",
    ...extra,
  });

  return { verifier, path: `/api/auth/oauth2/authorize?${query}` };
}

async function authorize(clientId: string, resource = resourceA, scope?: string) {
  const flow = authorization(
    clientId,
    resource,
    scope ? { scope } : resource === resourceB ? { scope: "offline_access reports:read" } : {},
  );

  const response = await request(flow.path);
  expect(response.status, await response.clone().text()).toBe(302);
  const location = new URL(response.headers.get("location")!, settings.baseURL);
  expect(location.pathname).toBe("/consent");

  const result = await request("/api/auth/oauth2/consent", {
    accept: true,
    oauth_query: location.search.slice(1),
  });

  expect(result.status, await result.clone().text()).toBe(200);
  const redirect = new URL((await result.json()).url);
  expect(redirect.searchParams.get("state")).toBe("state-to-validate");
  expect(redirect.searchParams.get("iss")).toBe(`${settings.baseURL}/api/auth`);

  return { code: redirect.searchParams.get("code")!, verifier: flow.verifier };
}

async function tokens(
  clientId: string,
  resource = resourceA,
  authorization?: string,
  scope?: string,
) {
  const grant = await authorize(clientId, resource, scope);

  const response = await request(
    "/api/auth/oauth2/token",
    {
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: "http://127.0.0.1:9876/callback",
      code: grant.code,
      code_verifier: grant.verifier,
      resource,
    },
    { anonymous: true, form: true, authorization },
  );

  expect(response.status, await response.clone().text()).toBe(200);

  return response.json();
}

beforeEach(async () => {
  applications = [];
  issuer = await openIssuer({ baseURL: "http://localhost:3000" });
  service = issuer.service;
  settings = issuer.settings;
  handle = createApplication();
  cookies = new Map();
});

afterEach(async () => {
  vi.restoreAllMocks();

  try {
    await stopCurrentGeneration();
  } finally {
    await issuer.close();
  }
});

async function setupOwner() {
  const response = await request("/api/issuer/setupOwner", { email, password });
  expect(response.status, await response.clone().text()).toBe(201);
}

async function restart() {
  await stopCurrentGeneration();
  issuer = await issuer.reopen();
  service = issuer.service;
  handle = createApplication();
}

describe("first-run setup", () => {
  test("fresh startup and restart permit setup, which signs the owner in and closes permanently", async () => {
    expect(await (await request("/api/issuer/setupStatus", {})).json()).toEqual({
      required: true,
    });
    await restart();
    const status = await request("/api/issuer/setupStatus", {});
    expect(await status.json()).toEqual({ required: true });
    expect(status.headers.get("cache-control")).toContain("no-store");
    expect((await request("/api/administration/listClients", {})).status).toBe(401);
    expect(
      (await request("/api/auth/sign-up/email", { email, password, name: "Owner" })).status,
    ).toBe(404);

    const created = await request("/api/issuer/setupOwner", {
      email: "Owner@Example.Internal",
      password,
    });

    expect(created.status, await created.clone().text()).toBe(201);
    expect(await created.json()).toEqual({ created: true });
    expect(created.headers.getSetCookie().join(";")).toContain("session_token");
    expect(created.headers.getSetCookie().join(";")).toContain("HttpOnly");
    expect((await Effect.runPromise(service.sql`SELECT count(*) AS n FROM session`))[0]).toEqual({
      n: 1,
    });
    expect(
      (await Effect.runPromise(service.sql`SELECT name, email, emailVerified FROM user`))[0],
    ).toEqual({
      name: "Owner",
      email,
      emailVerified: 0,
    });
    const owner = await Effect.runPromise(service.owner());
    expect(owner).toBeTypeOf("string");
    expect(await (await request("/api/issuer/setupStatus", {})).json()).toEqual({
      required: false,
    });
    // The setup cookie is the owner session; no separate sign-in is needed.
    expect((await request("/api/administration/listClients", {})).status).toBe(200);
    expect((await request("/api/administration/listClients", {}, { anonymous: true })).status).toBe(
      401,
    );
    expect((await login()).status).toBe(200);
    await restart();
    expect(await Effect.runPromise(service.owner())).toBe(owner);
    expect(await (await request("/api/issuer/setupStatus", {})).json()).toEqual({
      required: false,
    });
    expect((await request("/api/administration/listClients", {})).status).toBe(200);
    expect((await request("/api/issuer/setupOwner", { email, password })).status).toBe(409);
    // The provider's own sign-up is closed by the user-creation hook once the account exists.
    await expect(
      service.auth.api.signUpEmail({
        body: { email: "second@example.internal", password, name: "Owner" },
      }),
    ).rejects.toMatchObject({ statusCode: 409, message: "Setup already completed" });
    expect((await Effect.runPromise(service.sql`SELECT count(*) AS n FROM user`))[0]).toEqual({
      n: 1,
    });
  });

  test("invalid setup input and encoding never create an account", async () => {
    for (const body of [
      {},
      null,
      [],
      { email: "invalid", password },
      { email: ".owner@example.internal", password },
      { email: "owner..name@example.internal", password },
      { email: "owner@example.123", password },
      { email, password: "x".repeat(7) },
      { email, password: "x".repeat(129) },
      { email: 42, password },
      { email, password: 42 },
    ]) {
      const response = await handle(
        new Request(`${settings.baseURL}/api/issuer/setupOwner`, {
          method: "POST",
          headers: { origin: settings.baseURL, "content-type": "application/json" },
          body: JSON.stringify(body),
        }),
      );

      expect(response.status, await response.clone().text()).toBe(400);
    }

    for (const [contentType, body] of [
      ["application/json", "{"],
      ["text/plain", JSON.stringify({ email, password })],
      ["application/x-www-form-urlencoded", new URLSearchParams({ email, password }).toString()],
    ]) {
      const response = await handle(
        new Request(`${settings.baseURL}/api/issuer/setupOwner`, {
          method: "POST",
          headers: { origin: settings.baseURL, "content-type": contentType! },
          body,
        }),
      );

      expect(response.status).toBe(contentType === "application/json" ? 400 : 415);
      expect(await response.text()).not.toContain(password);
    }

    expect((await Effect.runPromise(service.sql`SELECT count(*) AS n FROM user`))[0]).toEqual({
      n: 0,
    });
    expect(await Effect.runPromise(service.owner())).toBeUndefined();
    await setupOwner();
  });

  test.each([
    "  Owner+Tag@Example.Internal  ",
    "owner'name@example.internal",
    `${"a".repeat(237)}@example.internal`,
  ])("setup email %s remains usable for provider login", async (input) => {
    const response = await request("/api/issuer/setupOwner", { email: input, password });
    expect(response.status).toBe(201);
    const normalized = input.trim().toLowerCase();
    expect((await Effect.runPromise(service.sql`SELECT email FROM user`))[0]).toEqual({
      email: normalized,
    });
    expect((await request("/api/auth/sign-in/email", { email: normalized, password })).status).toBe(
      200,
    );
  });

  test("simultaneous submissions create exactly one owner", async () => {
    const responses = await Promise.all([
      request("/api/issuer/setupOwner", { email, password }),
      request("/api/issuer/setupOwner", { email: "second@example.internal", password }),
    ]);

    expect(responses.map((response) => response.status).sort((a, b) => a - b)).toEqual([201, 409]);

    for (const table of ["user", "account", "session"])
      expect(
        (await Effect.runPromise(service.sql`SELECT count(*) AS n FROM ${query.table(table)}`))[0],
      ).toEqual({ n: 1 });
  });

  test("simultaneous submissions with the same email report the loser as a conflict", async () => {
    const responses = await Promise.all([
      request("/api/issuer/setupOwner", { email, password }),
      request("/api/issuer/setupOwner", { email, password: `${password} other` }),
    ]);

    expect(responses.map((response) => response.status).sort((a, b) => a - b)).toEqual([201, 409]);
    expect((await Effect.runPromise(service.sql`SELECT count(*) AS n FROM user`))[0]).toEqual({
      n: 1,
    });
  });

  test("a failed credential insert rolls back the account and permits retry", async () => {
    await Effect.runPromise(
      service.sql`CREATE TRIGGER fail_setup BEFORE INSERT ON account
      BEGIN SELECT RAISE(ABORT, 'Injected credential failure'); END`,
    );
    const failed = await request("/api/issuer/setupOwner", { email, password });
    expect(failed.status).toBe(500);
    const error = await failed.text();
    expect(error).not.toContain(password);
    expect(error).not.toContain("Injected credential failure");

    for (const table of ["user", "account", "session"])
      expect(
        (await Effect.runPromise(service.sql`SELECT count(*) AS n FROM ${query.table(table)}`))[0],
      ).toEqual({ n: 0 });
    expect(await (await request("/api/issuer/setupStatus", {})).json()).toEqual({
      required: true,
    });
    await Effect.runPromise(service.sql`DROP TRIGGER fail_setup`);
    await setupOwner();
    expect((await login()).status).toBe(200);
  });
});

describe("owner boundary", () => {
  beforeEach(setupOwner);
  test("serves the built web workspace rather than the server working directory", async () => {
    const assets = new Set<string>();

    for (const path of ["/", "/setup", "/login", "/consent"]) {
      const response = await request(path);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("text/html");
      const html = await response.text();
      expect(html).toContain("<title>Clanker Auth</title>");
      const references = [...html.matchAll(/(?:src|href)="(\/assets\/[^" ]+)"/g)];
      expect(references.length).toBeGreaterThan(0);

      for (const reference of references) assets.add(reference[1]!);
    }

    for (const asset of assets) {
      const result = await request(asset);
      expect(result.status).toBe(200);
      expect(result.headers.get("content-type")).toBe(
        asset.endsWith(".js") ? "text/javascript" : "text/css",
      );
      expect(await result.text()).not.toBe("");
    }

    expect((await request("/src/main.ts")).status).toBe(404);
  });

  test("login throttles brute force without exposing passwords", async () => {
    for (let i = 0; i < 5; i++) expect((await login("deliberately incorrect")).status).toBe(401);
    const limited = await login();
    expect(limited.status).toBe(429);
    expect(await limited.text()).not.toContain(password);
  });

  test("closed signup, protected admin, SameSite cookies, credential login and logout", async () => {
    expect((await request("/api/administration/listClients", {}, { anonymous: true })).status).toBe(
      401,
    );
    expect(
      (
        await request("/api/auth/sign-up/email", {
          email: "stranger@example.internal",
          password,
          name: "Intruder",
        })
      ).status,
    ).toBe(404);
    await expect(
      service.auth.api.signUpEmail({
        body: { email: "stranger@example.internal", password, name: "Intruder" },
      }),
    ).rejects.toMatchObject({ statusCode: 409 });
    expect((await login("incorrect password")).status).toBe(401);
    const signedIn = await login();
    expect(signedIn.status).toBe(200);
    expect(signedIn.headers.getSetCookie().join(";")).toContain("HttpOnly");
    // The session cookie is the CSRF boundary for owner actions; Origin is not inspected.
    expect(signedIn.headers.getSetCookie().join(";")).toContain("SameSite=Lax");
    const session = await request("/api/auth/get-session");
    expect(session.status).toBe(200);
    const current = await session.json();
    expect(current.user.id).toBe(await Effect.runPromise(service.owner()));
    expect(session.headers.has("set-auth-jwt")).toBe(false);
    expect((await request("/api/administration/listClients", {})).status).toBe(200);
    expect(
      (await request("/api/auth/oauth2/create-client", { redirect_uris: ["https://evil.example"] }))
        .status,
    ).toBe(404);
    expect((await request("/api/auth/token")).status).toBe(404);
    expect((await request("/api/auth/sign-out", {})).status).toBe(200);
    expect((await request("/api/administration/listClients", {})).status).toBe(401);
  });
});

describe("OAuth boundaries and lifecycle", () => {
  beforeEach(setupOwner);
  test("the owner's session is the single sign-on session: 30 days, renewed by application sign-in", async () => {
    const day = 24 * 60 * 60 * 1000;

    const expiry = async () => {
      const response = await request("/api/auth/get-session");
      expect(response.status).toBe(200);

      return Date.parse((await response.json()).session.expiresAt);
    };

    await login();
    const app = await client();
    const initial = await expiry();
    expect(initial - Date.now()).toBeGreaterThan(29 * day);
    expect(initial - Date.now()).toBeLessThanOrEqual(30 * day);
    vi.useFakeTimers({ toFake: ["Date"] });

    try {
      vi.setSystemTime(Date.now() + 2 * day);
      const redirect = await request(unprompted(app.client_id).path);
      expect(redirect.status, await redirect.clone().text()).toBe(302);
      expect(redirect.headers.getSetCookie().join(";")).toContain("session_token");
      const renewed = await expiry();
      expect(renewed).toBeGreaterThan(initial + day);
      expect(renewed - Date.now()).toBeLessThanOrEqual(30 * day);
    } finally {
      vi.useRealTimers();
    }
  });

  test("managed clients are first party: a signed-in owner is redirected without consent", async () => {
    await login();
    const app = await client();
    const flow = unprompted(app.client_id);
    const response = await request(flow.path);
    expect(response.status, await response.clone().text()).toBe(302);
    const redirect = new URL(response.headers.get("location")!);
    expect(`${redirect.origin}${redirect.pathname}`).toBe("http://127.0.0.1:9876/callback");
    expect(redirect.searchParams.get("state")).toBe("state-to-validate");
    expect(
      await Effect.runPromise(
        service.sql`SELECT id FROM oauthConsent WHERE clientId = ${app.client_id}`,
      ),
    ).toEqual([]);

    const issued = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "authorization_code",
        client_id: app.client_id,
        redirect_uri: "http://127.0.0.1:9876/callback",
        code: redirect.searchParams.get("code"),
        code_verifier: flow.verifier,
        resource: resourceA,
      },
      { anonymous: true, form: true },
    );

    expect(issued.status, await issued.clone().text()).toBe(200);
    expect((await issued.json()).scope.split(" ")).toContain("notes:read");
    // An explicit prompt still asks, and automatic clients always ask.
    const prompted = await request(authorization(app.client_id).path);
    expect(new URL(prompted.headers.get("location")!, settings.baseURL).pathname).toBe("/consent");
    const dynamic = await dynamicClient();
    const asked = await request(unprompted(dynamic.client_id).path);
    expect(new URL(asked.headers.get("location")!, settings.baseURL).pathname).toBe("/consent");
  });

  test("confidential Basic authentication, rotation, introspection, logout and client deletion", async () => {
    await login();
    const app = await client(resourceA, true);
    expect(app.client_secret).toBeTypeOf("string");
    const listing = await (await request("/api/administration/listClients", {})).json();
    expect(JSON.stringify(listing)).not.toContain(app.client_secret);
    const grant = await authorize(app.client_id);

    const basic = (secret: string) =>
      `Basic ${Buffer.from(`${app.client_id}:${secret}`).toString("base64")}`;

    const exchange = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "authorization_code",
        client_id: app.client_id,
        redirect_uri: "http://127.0.0.1:9876/callback",
        code: grant.code,
        code_verifier: grant.verifier,
        resource: resourceA,
      },
      {
        anonymous: true,
        form: true,
        authorization: basic(app.client_secret),
        origin: "https://client.example",
      },
    );

    expect(exchange.status, await exchange.clone().text()).toBe(200);
    expect(exchange.headers.get("access-control-allow-origin")).toBe("*");
    const issued = await exchange.json();

    const introspect = (secret: string) =>
      request(
        "/api/auth/oauth2/introspect",
        { token: issued.access_token },
        { anonymous: true, form: true, authorization: basic(secret) },
      );

    expect((await (await introspect(app.client_secret)).json()).active).toBe(true);

    const rotated = await (
      await request("/api/administration/rotateClientSecret", { client_id: app.client_id })
    ).json();

    expect(rotated.client_secret).toBeTypeOf("string");
    expect(rotated.client_secret).not.toBe(app.client_secret);
    expect((await introspect(app.client_secret)).status).toBe(401);
    expect((await (await introspect(rotated.client_secret)).json()).active).toBe(true);
    await request("/api/auth/sign-out", {});
    expect((await (await introspect(rotated.client_secret)).json()).active).toBe(false);
    await login();
    expect(
      (await request("/api/administration/deleteClient", { client_id: app.client_id })).status,
    ).toBe(200);
    expect((await (await request("/api/administration/listClients", {})).json()).clients).toEqual(
      [],
    );

    const refresh = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "refresh_token",
        client_id: app.client_id,
        refresh_token: issued.refresh_token,
        resource: resourceA,
      },
      { anonymous: true, form: true, authorization: basic(rotated.client_secret) },
    );

    expect(refresh.status, await refresh.clone().text()).toBe(400);
    expect((await refresh.json()).error).toBe("invalid_grant");
  });

  test("discovery pins issuer and advertises S256 and automatic onboarding without machine grants", async () => {
    for (const path of [
      "/.well-known/oauth-authorization-server/api/auth",
      "/api/auth/.well-known/oauth-authorization-server",
    ]) {
      const response = await request(path);
      expect(response.status, await response.clone().text()).toBe(200);
      const metadata = await response.json();
      expect(metadata.issuer).toBe(`${settings.baseURL}/api/auth`);
      expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
      expect(metadata.registration_endpoint).toBe(`${settings.baseURL}/api/auth/oauth2/register`);
      expect(metadata.client_id_metadata_document_supported).toBe(true);
      expect(metadata.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    }
  });

  test("scopes no resource defines are refused before consent", async () => {
    await login();
    const app = await client();

    const response = await request(
      authorization(app.client_id, resourceA, { scope: "notes:read notes:nope" }).path,
    );

    expect(response.status, await response.clone().text()).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.origin + location.pathname).toBe("http://127.0.0.1:9876/callback");
    expect(location.searchParams.get("error")).toBe("invalid_scope");
  });

  test("login continuation and signed consent denial; altered consent is rejected", async () => {
    await login();
    const app = await client();
    cookies.clear();
    const flow = authorization(app.client_id);
    const response = await request(flow.path);
    const location = new URL(response.headers.get("location")!, settings.baseURL);
    expect(location.pathname).toBe("/login");

    const signedIn = await request("/api/auth/sign-in/email", {
      email,
      password,
      oauth_query: location.search.slice(1),
    });

    expect(signedIn.status, await signedIn.clone().text()).toBe(200);
    const continued = new URL((await signedIn.json()).url, settings.baseURL);
    expect(continued.pathname).toBe("/consent");
    const tampered = new URL(continued);
    tampered.searchParams.set("resource", resourceB);
    expect(
      (
        await request("/api/auth/oauth2/consent", {
          accept: true,
          oauth_query: tampered.search.slice(1),
        })
      ).status,
    ).toBe(400);

    const denied = await request("/api/auth/oauth2/consent", {
      accept: false,
      oauth_query: continued.search.slice(1),
    });

    expect(denied.status).toBe(200);
    const result = new URL((await denied.json()).url);
    expect(result.searchParams.get("error")).toBe("access_denied");
    expect(result.searchParams.get("code")).toBeNull();
  });

  test("S256, redirect matching, single-resource authorization and per-client audience enforcement", async () => {
    await login();
    const app = await client();

    const invalidRequests: Record<string, string>[] = [
      { code_challenge_method: "plain" },
      { redirect_uri: "http://127.0.0.1:9876/evil" },
      { resource: resourceB },
      { resource: "" },
    ];

    for (const extra of invalidRequests) {
      const response = await request(authorization(app.client_id, resourceA, extra).path);
      const text = await response.text();
      expect(
        response.status >= 400 || response.headers.get("location")?.includes("error="),
        text,
      ).toBeTruthy();
    }

    const multiple = await request(
      `${authorization(app.client_id).path}&resource=${encodeURIComponent(resourceB)}`,
    );

    expect((await multiple.json()).error).toBe("invalid_target");
    const grant = await authorize(app.client_id);

    const wrongVerifier = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "authorization_code",
        client_id: app.client_id,
        redirect_uri: "http://127.0.0.1:9876/callback",
        code: grant.code,
        code_verifier: "x".repeat(43),
        resource: resourceA,
      },
      { form: true, anonymous: true },
    );

    expect(wrongVerifier.status).toBe(401);
    expect((await wrongVerifier.json()).error).toBe("invalid_request");
  });

  test("issued JWT claims and signing keys remain valid across restart", async () => {
    await login();
    const a = await client();
    const b = await client(resourceB);
    const tokenA = await tokens(a.client_id);
    const tokenB = await tokens(b.client_id, resourceB);
    const jwks = await (await request("/api/auth/jwks")).json();
    const keys = createLocalJWKSet(jwks);

    const verified = await jwtVerify(tokenA.access_token, keys, {
      issuer: `${settings.baseURL}/api/auth`,
      audience: resourceA,
      typ: "at+jwt",
    });

    // Exactly the requested resource: no UserInfo or other downstream audience.
    expect(verified.payload.aud).toEqual(resourceA);
    expect(verified.payload.scope).toContain("notes:read");
    expect(verified.payload.exp! - verified.payload.iat!).toBeLessThanOrEqual(900);

    const verifiedB = await jwtVerify(tokenB.access_token, keys, {
      issuer: `${settings.baseURL}/api/auth`,
      audience: resourceB,
      typ: "at+jwt",
    });

    expect(verifiedB.payload.aud).not.toContain(resourceA);
    await restart();
    expect(await (await request("/api/auth/jwks")).json()).toEqual(jwks);
    expect((await request("/api/administration/listClients", {})).status).toBe(200);

    const refresh = await request(
      "/api/auth/oauth2/token",
      {
        grant_type: "refresh_token",
        client_id: a.client_id,
        refresh_token: tokenA.refresh_token,
        resource: resourceA,
      },
      { anonymous: true, form: true },
    );

    expect(refresh.status, await refresh.clone().text()).toBe(200);
  });

  test("refresh is resource-bound, rotates with a reuse window, detects replay, and revokes", async () => {
    await login();
    const app = await client();
    const original = await tokens(app.client_id);

    const refresh = (token: string, resource?: string) =>
      request(
        "/api/auth/oauth2/token",
        resource === undefined
          ? { grant_type: "refresh_token", client_id: app.client_id, refresh_token: token }
          : {
              grant_type: "refresh_token",
              client_id: app.client_id,
              refresh_token: token,
              resource,
            },
        { form: true, anonymous: true },
      );

    expect((await refresh(original.refresh_token, resourceB)).status).toBe(400);
    const rotatedResponse = await refresh(original.refresh_token, resourceA);
    expect(rotatedResponse.status, await rotatedResponse.clone().text()).toBe(200);
    const rotated = await rotatedResponse.json();
    expect(rotated.refresh_token).not.toBe(original.refresh_token);
    // A retried refresh inside the reuse window replays the same replacement.
    const replayed = await refresh(original.refresh_token, resourceA);
    expect(replayed.status, await replayed.clone().text()).toBe(200);
    expect((await replayed.json()).refresh_token).toBe(rotated.refresh_token);
    // Omitting resource reuses the resource bound to the refresh token.
    const bare = await refresh(rotated.refresh_token);
    expect(bare.status, await bare.clone().text()).toBe(200);
    const next = await bare.json();
    const keys = createLocalJWKSet(await (await request("/api/auth/jwks")).json());
    await jwtVerify(next.access_token, keys, { audience: resourceA });
    vi.useFakeTimers({ toFake: ["Date"] });

    try {
      vi.setSystemTime(Date.now() + 31_000);
      // Outside the window, replaying a rotated token revokes the whole family.
      expect((await refresh(rotated.refresh_token, resourceA)).status).toBe(400);
      expect((await refresh(next.refresh_token, resourceA)).status).toBe(400);
    } finally {
      vi.useRealTimers();
    }

    const another = await tokens(app.client_id);

    const revoked = await request(
      "/api/auth/oauth2/revoke",
      { token: another.refresh_token, token_type_hint: "refresh_token", client_id: app.client_id },
      { form: true, anonymous: true },
    );

    expect(revoked.status).toBe(200);
    expect((await refresh(another.refresh_token)).status).toBe(400);

    const jwtRevocation = await request(
      "/api/auth/oauth2/revoke",
      { token: another.access_token, token_type_hint: "access_token", client_id: app.client_id },
      { form: true, anonymous: true },
    );

    expect(jwtRevocation.status).toBe(400);
    expect((await jwtRevocation.json()).error).toBe("unsupported_token_type");
  });
});

describe("dashboard resources and client access", () => {
  beforeEach(async () => {
    await setupOwner();
    expect((await login()).status).toBe(200);
  });

  const listing = async () => (await request("/api/administration/listClients", {})).json();

  const access = (clientId: string, resources: string[]) =>
    request("/api/administration/setClientAccess", { client_id: clientId, resources });

  const updateResource = (identifier: string, scopes: string[], name = "Updated resource") =>
    request("/api/administration/updateResource", { identifier, name, scopes });

  const exchange = (
    clientId: string,
    grant: { code: string; verifier: string },
    resource: string,
  ) =>
    request(
      "/api/auth/oauth2/token",
      {
        grant_type: "authorization_code",
        client_id: clientId,
        redirect_uri: "http://127.0.0.1:9876/callback",
        code: grant.code,
        code_verifier: grant.verifier,
        resource,
      },
      { anonymous: true, form: true },
    );

  const refresh = (clientId: string, token: string, resource: string) =>
    request(
      "/api/auth/oauth2/token",
      {
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: token,
        resource,
      },
      { anonymous: true, form: true },
    );

  test("the built-in administration resource survives restart and user resource CRUD persists", async () => {
    expect((await listing()).resources).toEqual([administrationResource(settings.baseURL)]);
    await restart();
    expect((await listing()).resources).toEqual([administrationResource(settings.baseURL)]);
    const resource = { identifier: resourceA, name: "Personal MCP", scopes: ["read", "write"] };
    expect((await request("/api/administration/createResource", resource)).status).toBe(201);
    expect((await request("/api/administration/createResource", resource)).status).toBe(400);
    expect((await updateResource(resourceA, ["read"], "Renamed MCP")).status).toBe(200);
    await restart();
    expect((await listing()).resources).toEqual([
      administrationResource(settings.baseURL),
      { ...resource, name: "Renamed MCP", scopes: ["read"], builtIn: false },
    ]);
    expect(
      (await request("/api/administration/deleteResource", { identifier: resourceA })).status,
    ).toBe(200);
    await restart();
    expect((await listing()).resources).toEqual([administrationResource(settings.baseURL)]);
    expect((await updateResource(resourceA, ["read"])).status).toBe(404);
    expect(
      (await request("/api/administration/deleteResource", { identifier: resourceA })).status,
    ).toBe(404);
  });

  test("resource mutations reject invalid input and unauthorized requests but accept older valid sessions", async () => {
    const valid = { identifier: resourceA, name: "MCP", scopes: ["read"] };

    for (const input of [
      { ...valid, identifier: "not a uri" },
      { ...valid, identifier: "https://api.internal/#fragment" },
      { ...valid, name: " " },
      { ...valid, scopes: ["read write"] },
      { ...valid, scopes: ['read"write'] },
      { ...valid, scopes: ["read\\write"] },
      { ...valid, scopes: ["read\twrite"] },
      { ...valid, scopes: ["réad"] },
      { ...valid, scopes: ["offline_access"] },
      { ...valid, scopes: [42] },
    ]) {
      expect(
        (await request("/api/administration/createResource", input)).status,
        JSON.stringify(input),
      ).toBe(400);
    }

    expect(
      (await request("/api/administration/createResource", valid, { anonymous: true })).status,
    ).toBe(401);
    expect((await listing()).resources).toEqual([administrationResource(settings.baseURL)]);
    const { context } = service;
    const ownerId = await Effect.runPromise(service.owner());

    if (ownerId === undefined) throw new Error("Missing test owner");
    await context.adapter.update({
      model: "session",
      where: [{ field: "userId", value: ownerId }],
      update: { createdAt: new Date(Date.now() - 16 * 60_000) },
    });
    expect((await request("/api/administration/createResource", valid)).status).toBe(201);
    expect((await listing()).resources).toEqual([
      administrationResource(settings.baseURL),
      { ...valid, builtIn: false },
    ]);

    const created = await request("/api/administration/createClient", {
      client_name: "Older session client",
      redirect_uris: ["http://127.0.0.1:9876/callback"],
      resources: [],
      application_type: "native",
      token_endpoint_auth_method: "client_secret_basic",
    });

    expect(created.status, await created.clone().text()).toBe(201);
    const app = await created.json();
    expect(
      (
        await request("/api/administration/rotateClientSecret", {
          client_id: app.client_id,
        })
      ).status,
    ).toBe(200);
  });

  test("domain refusals and internal failures share one wire vocabulary", async () => {
    const resource = { identifier: resourceA, name: "Notes MCP", scopes: ["notes:read"] };
    expect((await request("/api/administration/createResource", resource)).status).toBe(201);

    const reserved = await request("/api/administration/deleteResource", {
      identifier: `${settings.baseURL}/mcp`,
    });

    expect(reserved.status).toBe(400);
    expect(await reserved.json()).toEqual(
      Schema.encodeSync(BadRequest)(
        new BadRequest({ error: "The administration Resource is reserved" }),
      ),
    );

    // The provider bridge declares no refusal of its own. A catalogue row this issuer
    // can no longer read is its own failure, answered exactly as the action API answers.
    await Effect.runPromise(
      service.sql`UPDATE oauthResource SET allowedScopes = 'not json' WHERE identifier = ${resourceA}`,
    );

    const authorize = await request(
      `/api/auth/oauth2/authorize?client_id=unused&resource=${encodeURIComponent(resourceA)}`,
      undefined,
      { anonymous: true },
    );

    expect(authorize.status).toBe(500);
    expect(await authorize.json()).toEqual(
      Schema.encodeSync(InternalServerError)(
        new InternalServerError({ error: "Request could not be completed" }),
      ),
    );
  });

  test("resources accept any absolute URI and may define no custom scopes", async () => {
    const urn = { identifier: "urn:example:reports", name: "Reports", scopes: [] };
    expect((await request("/api/administration/createResource", urn)).status).toBe(201);
    expect((await listing()).resources).toEqual([
      administrationResource(settings.baseURL),
      { ...urn, builtIn: false },
    ]);
    expect((await updateResource(urn.identifier, [], "Renamed reports")).status).toBe(200);
    expect(
      (await request("/api/administration/deleteResource", { identifier: urn.identifier })).status,
    ).toBe(200);
  });

  test("managed clients accept several redirect URIs and can be edited", async () => {
    const created = await request("/api/administration/createClient", {
      client_name: "Multi-callback client",
      redirect_uris: ["http://127.0.0.1:9876/callback", "http://localhost:5173/callback"],
      resources: [],
      application_type: "native",
      token_endpoint_auth_method: "client_secret_post",
    });

    expect(created.status, await created.clone().text()).toBe(201);
    const app = await created.json();
    expect(app.redirect_uris).toEqual([
      "http://127.0.0.1:9876/callback",
      "http://localhost:5173/callback",
    ]);
    expect(app.token_endpoint_auth_method).toBe("client_secret_post");

    const updated = await request("/api/administration/updateClient", {
      client_id: app.client_id,
      client_name: "Renamed client",
      redirect_uris: ["https://app.internal/callback"],
      application_type: "web",
    });

    expect(updated.status, await updated.clone().text()).toBe(200);
    expect(await updated.json()).toMatchObject({
      client_id: app.client_id,
      client_name: "Renamed client",
      redirect_uris: ["https://app.internal/callback"],
      application_type: "web",
    });

    const stored = (await listing()).clients.find(
      (row: { client_id: string }) => row.client_id === app.client_id,
    );

    expect(stored).toMatchObject({
      client_name: "Renamed client",
      redirect_uris: ["https://app.internal/callback"],
      application_type: "web",
    });
    expect(
      (
        await request("/api/administration/updateClient", {
          client_id: app.client_id,
          client_name: "Loopback web client",
          redirect_uris: ["http://127.0.0.1:9876/callback"],
          application_type: "web",
        })
      ).status,
    ).toBe(400);
  });

  test("a client registered without resources can later authorize an HTTP resource with basic scope tokens", async () => {
    const created = await request("/api/administration/createClient", {
      client_name: "Client before resources",
      redirect_uris: ["http://127.0.0.1:9876/callback"],
      resources: [],
      application_type: "native",
      token_endpoint_auth_method: "none",
    });

    expect(created.status, await created.clone().text()).toBe(201);
    const app = await created.json();
    expect((await listing()).clientAccess).toEqual([]);
    expect((await listing()).resources).toEqual([administrationResource(settings.baseURL)]);

    const resource = {
      identifier: "http://api.internal/mcp",
      name: "HTTP resource",
      scopes: ["r", "Files.Read", "read_all"],
    };

    const added = await request("/api/administration/createResource", resource);
    expect(added.status, await added.clone().text()).toBe(201);
    const flow = authorization(app.client_id, resource.identifier, { scope: "r" });
    const denied = await request(flow.path);
    expect(denied.status).not.toBe(200);
    expect(denied.headers.get("location") ?? "").not.toContain("/consent");
    expect((await access(app.client_id, [resource.identifier])).status).toBe(200);

    const issued = await tokens(
      app.client_id,
      resource.identifier,
      undefined,
      resource.scopes.join(" "),
    );

    const keys = createLocalJWKSet(await (await request("/api/auth/jwks")).json());

    const { payload: claims } = await jwtVerify(issued.access_token, keys, {
      issuer: `${settings.baseURL}/api/auth`,
      audience: resource.identifier,
      typ: "at+jwt",
    });

    expect(claims.aud).toBe(resource.identifier);
    expect(new Set(String(claims.scope).split(" "))).toEqual(new Set(resource.scopes));
  });

  test("one client accesses multiple resources but each token request targets one", async () => {
    const app = await client();
    expect((await access(app.client_id, [resourceA, resourceB])).status).toBe(200);
    const rows = (await listing()).clientAccess;
    expect(rows).toEqual(
      expect.arrayContaining([
        { client_id: app.client_id, resource: resourceA },
        { client_id: app.client_id, resource: resourceB },
      ]),
    );
    expect((await tokens(app.client_id, resourceA)).access_token).toBeTypeOf("string");
    expect((await tokens(app.client_id, resourceB)).access_token).toBeTypeOf("string");
    expect((await access(app.client_id, [resourceA, "https://missing.internal/api"])).status).toBe(
      400,
    );
    expect((await listing()).clientAccess).toEqual(rows);
    expect((await access(app.client_id, [])).status).toBe(200);
    expect((await listing()).clientAccess).toEqual([]);
    expect(
      (await request("/api/administration/deleteResource", { identifier: resourceA })).status,
    ).toBe(200);
  });

  test("filtered access preserves ordering and isolates clients sharing a resource", async () => {
    const first = await client();
    const second = await client();
    const linked = await access(first.client_id, [resourceB, resourceA]);
    expect(linked.status).toBe(200);
    expect((await linked.json()).clientAccess).toEqual([
      { client_id: first.client_id, resource: resourceA },
      { client_id: first.client_id, resource: resourceB },
    ]);
    expect(await Effect.runPromise(service.resources.hasAccess(first.client_id, resourceB))).toBe(
      true,
    );
    expect(await Effect.runPromise(service.resources.hasAccess(second.client_id, resourceB))).toBe(
      false,
    );
    expect(await Effect.runPromise(service.resources.hasAccess("missing", resourceA))).toBe(false);
    expect((await access(first.client_id, [])).status).toBe(200);
    expect((await listing()).clientAccess).toEqual([
      { client_id: second.client_id, resource: resourceA },
    ]);
    expect(
      (await request("/api/administration/deleteResource", { identifier: resourceA })).status,
    ).toBe(200);
    expect((await listing()).clientAccess).toEqual([]);
    expect(
      (await request("/api/administration/deleteResource", { identifier: resourceB })).status,
    ).toBe(200);
  });

  test("the same scope label has independent consent on each resource", async () => {
    const app = await dynamicClient();
    expect((await updateResource(resourceB, ["notes:read", "notes:write"])).status).toBe(200);
    await authorize(app.client_id, resourceA);
    const responseB = await request(unprompted(app.client_id, resourceB).path);
    const consentB = new URL(responseB.headers.get("location")!, settings.baseURL);
    expect(consentB.pathname).toBe("/consent");
    expect(
      (
        await request("/api/auth/oauth2/consent", {
          accept: true,
          oauth_query: consentB.search.slice(1),
        })
      ).status,
    ).toBe(200);

    const consents = await Effect.runPromise(
      service.sql`SELECT referenceId, resources FROM oauthConsent WHERE clientId = ${app.client_id} ORDER BY referenceId`,
    );

    expect(consents).toEqual(
      [
        { referenceId: `resource:${resourceA}`, resources: JSON.stringify([resourceA]) },
        { referenceId: `resource:${resourceB}`, resources: JSON.stringify([resourceB]) },
      ].sort((a, b) => a.referenceId.localeCompare(b.referenceId)),
    );

    for (const resource of [resourceA, resourceB]) {
      const prior = await request(authorization(app.client_id, resource, { prompt: "none" }).path);
      const redirect = new URL(prior.headers.get("location")!, settings.baseURL);
      expect(redirect.searchParams.has("code")).toBe(true);
      expect(redirect.searchParams.has("error")).toBe(false);
    }
  });

  test("new scopes appear immediately and need consent; name-only changes preserve refresh grants", async () => {
    const app = await dynamicClient();
    const issued = await tokens(app.client_id);
    expect((await updateResource(resourceA, ["notes:read", "notes:write"], "Renamed")).status).toBe(
      200,
    );
    expect((await refresh(app.client_id, issued.refresh_token, resourceA)).status).toBe(200);
    expect(
      (await updateResource(resourceA, ["notes:read", "notes:write", "notes:admin"])).status,
    ).toBe(200);

    const metadata = await (
      await request("/.well-known/oauth-authorization-server/api/auth")
    ).json();

    expect(metadata.scopes_supported).toContain("notes:admin");

    const stored = (await listing()).clients.find(
      (row: { client_id: string }) => row.client_id === app.client_id,
    );

    expect(stored.scope.split(" ")).toContain("notes:admin");

    const response = await request(
      authorization(app.client_id, resourceA, { scope: "notes:admin", prompt: "none" }).path,
    );

    expect(
      new URL(response.headers.get("location")!, settings.baseURL).searchParams.get("error"),
    ).toBe("consent_required");
  });

  test("scope removal narrows issued scopes while unconsumed grants retain their original consent", async () => {
    const app = await client();
    expect((await access(app.client_id, [resourceA, resourceB])).status).toBe(200);
    expect((await updateResource(resourceB, ["notes:read", "notes:write"])).status).toBe(200);
    const sharedScopes = "offline_access notes:read";
    const issuedA = await tokens(app.client_id, resourceA);
    const retainedRefreshA = await tokens(app.client_id, resourceA);
    const issuedB = await tokens(app.client_id, resourceB, undefined, sharedScopes);
    const pendingA = await authorize(app.client_id, resourceA);
    const retainedA = await authorize(app.client_id, resourceA);
    const pendingB = await authorize(app.client_id, resourceB, sharedScopes);
    expect((await updateResource(resourceA, ["notes:write"])).status).toBe(200);
    const narrowed = await refresh(app.client_id, issuedA.refresh_token, resourceA);
    expect(narrowed.status).toBe(200);
    const narrowedToken = await narrowed.json();
    expect(narrowedToken.scope.split(" ")).not.toContain("notes:read");
    const keys = createLocalJWKSet(await (await request("/api/auth/jwks")).json());
    const verified = await jwtVerify(narrowedToken.access_token, keys, { audience: resourceA });
    expect(String(verified.payload.scope).split(" ")).not.toContain("notes:read");
    const narrowedCode = await exchange(app.client_id, pendingA, resourceA);
    expect(narrowedCode.status).toBe(200);
    expect((await narrowedCode.json()).scope.split(" ")).not.toContain("notes:read");
    expect((await refresh(app.client_id, issuedB.refresh_token, resourceB)).status).toBe(200);
    expect((await exchange(app.client_id, pendingB, resourceB)).status).toBe(200);
    expect((await updateResource(resourceA, ["notes:read", "notes:write"])).status).toBe(200);
    const restoredRefresh = await refresh(app.client_id, retainedRefreshA.refresh_token, resourceA);
    expect(restoredRefresh.status).toBe(200);
    expect((await restoredRefresh.json()).scope.split(" ")).toContain("notes:read");
    const restoredCode = await exchange(app.client_id, retainedA, resourceA);
    expect(restoredCode.status).toBe(200);
    expect((await restoredCode.json()).scope.split(" ")).toContain("notes:read");
    // Exchanging a code consumes it even when resource policy narrows its scopes.
    expect((await exchange(app.client_id, pendingA, resourceA)).status).toBe(400);
  });

  test("unlink denies access while re-add restores retained grants and consent", async () => {
    const app = await client();
    expect((await access(app.client_id, [resourceA, resourceB])).status).toBe(200);
    const issuedA = await tokens(app.client_id, resourceA);
    const issuedB = await tokens(app.client_id, resourceB);
    const pendingA = await authorize(app.client_id, resourceA);

    const consentsBefore = await Effect.runPromise(
      service.sql`SELECT * FROM oauthConsent WHERE clientId = ${app.client_id} ORDER BY id`,
    );

    expect((await access(app.client_id, [resourceB])).status).toBe(200);
    expect((await refresh(app.client_id, issuedA.refresh_token, resourceA)).status).toBe(400);
    expect(
      await Effect.runPromise(
        service.sql`SELECT * FROM oauthConsent WHERE clientId = ${app.client_id} ORDER BY id`,
      ),
    ).toEqual(consentsBefore);
    expect((await access(app.client_id, [resourceA, resourceB])).status).toBe(200);
    expect((await refresh(app.client_id, issuedA.refresh_token, resourceA)).status).toBe(200);
    expect((await exchange(app.client_id, pendingA, resourceA)).status).toBe(200);
    expect((await refresh(app.client_id, issuedB.refresh_token, resourceB)).status).toBe(200);
    const again = await request(authorization(app.client_id, resourceA, { prompt: "none" }).path);
    expect(new URL(again.headers.get("location")!, settings.baseURL).searchParams.has("code")).toBe(
      true,
    );

    const unaffected = await request(
      authorization(app.client_id, resourceB, {
        scope: "offline_access reports:read",
        prompt: "none",
      }).path,
    );

    expect(
      new URL(unaffected.headers.get("location")!, settings.baseURL).searchParams.has("code"),
    ).toBe(true);
  });

  test("a failed provider resource write preserves stored policy and live discovery", async () => {
    const app = await client();
    const before = await listing();

    const metadataBefore = await (
      await request("/.well-known/oauth-authorization-server/api/auth")
    ).json();

    await Effect.runPromise(
      service.sql`CREATE TRIGGER reject_scope_update BEFORE UPDATE OF allowedScopes ON oauthResource BEGIN SELECT RAISE(ABORT, 'injected scope failure'); END`,
    );

    try {
      expect((await updateResource(resourceA, ["notes:read", "new:scope"])).status).toBe(500);
      expect(await listing()).toEqual(before);

      const metadataAfter = await (
        await request("/.well-known/oauth-authorization-server/api/auth")
      ).json();

      expect(metadataAfter.scopes_supported).toEqual(metadataBefore.scopes_supported);
    } finally {
      await Effect.runPromise(service.sql`DROP TRIGGER reject_scope_update`);
    }

    expect((await tokens(app.client_id)).access_token).toBeTypeOf("string");
  });

  test("overlapping link and delete requests leave consistent resource access", async () => {
    const app = await client();

    const results = await Promise.all([
      access(app.client_id, [resourceA, resourceB]),
      request("/api/administration/deleteResource", { identifier: resourceB }),
    ]);

    // Linking wins, or loses at whichever provider step first sees the deleted resource.
    expect([200, 400, 404]).toContain(results[0]?.status);
    expect(results[1]?.status).toBe(200);
    const state = await listing();

    for (const link of state.clientAccess) {
      expect(
        state.resources.some(
          (resource: { identifier: string }) => resource.identifier === link.resource,
        ),
      ).toBe(true);
    }
  });
});
