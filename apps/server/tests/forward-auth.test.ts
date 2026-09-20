/** Forward auth: proxy subrequests turn the owner's session into resource access tokens. */
import { afterEach, beforeEach, expect, test } from "vite-plus/test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Schema } from "effect";
import { createLocalJWKSet, jwtVerify } from "jose";
import { webApplication as application } from "./web-application.ts";
import { initialize, openAuth, createOwner, type Service } from "../src/auth.ts";
import { forwardClientId, forwardCookie } from "../src/forward-auth.ts";
import { testSettings } from "./settings.ts";

const origin = "https://auth.home.example";

const resource = "https://notes.home.example/api";

const page = "https://notes.home.example/docs?x=1";

const owner = { email: "owner@example.internal", password: "test-only password123" };

let directory: string;

let service: Service;

let handle: ReturnType<typeof application>;

/** The issuer's own session cookie, as the dashboard holds it. */
let session: string;

const call = (path: string, body?: typeof Schema.Json.Type, headers: Record<string, string> = {}) =>
  handle(
    new Request(`${origin}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { origin, cookie: session, "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
    }),
  );

const continueTo = (rd: string, cookie = session) =>
  call(`/forward-auth/continue?rd=${encodeURIComponent(rd)}`, undefined, { cookie });

/** What Caddy's forward_auth or Traefik's forwardAuth sends for a browser request. */
const forward = (cookie: string, target = resource, original = page, mode = "navigate") => {
  const url = new URL(original);

  return handle(
    new Request(`${origin}/forward-auth?resource=${encodeURIComponent(target)}`, {
      headers: {
        cookie,
        "x-forwarded-proto": url.protocol.slice(0, -1),
        "x-forwarded-host": url.host,
        "x-forwarded-uri": `${url.pathname}${url.search}`,
        "sec-fetch-mode": mode,
      },
      redirect: "manual",
    }),
  );
};

const cookiePair = (response: Response, name: string) =>
  response.headers
    .getSetCookie()
    .map((cookie) => cookie.split(";")[0]!)
    .find((pair) => pair.startsWith(`${name}=`));

const redirectTo = (response: Response, path: string, rd = page) => {
  expect(response.status).toBe(302);
  const location = new URL(response.headers.get("location")!);
  expect(location.origin + location.pathname).toBe(`${origin}${path}`);
  expect(location.searchParams.get("rd")).toBe(rd);
};

/** Where login sends the browser afterwards: back through continue to the original page. */
const continueURL = (original = page) =>
  `${origin}/forward-auth/continue?rd=${encodeURIComponent(original)}`;

beforeEach(async () => {
  directory = mkdtempSync(join(tmpdir(), "clankerauth-forward-"));
  service = await Effect.runPromise(
    openAuth(
      testSettings({
        baseURL: origin,
        database: join(directory, "auth.sqlite"),
        cookieDomain: "home.example",
      }),
    ),
  );
  await Effect.runPromise(initialize(service));
  handle = application(service);
  await Effect.runPromise(createOwner(service, owner));
  session = "";
  const login = await call("/api/auth/sign-in/email", owner);
  expect(login.status).toBe(200);
  // The issuer session stays on the issuer host; only the forward cookie is shared.
  expect(login.headers.getSetCookie().join(";")).not.toContain("Domain=");
  session = login.headers
    .getSetCookie()
    .map((part) => part.split(";")[0])
    .join("; ");
  expect(
    (
      await call("/api/administration/createResource", {
        identifier: resource,
        name: "Notes",
        scopes: ["notes:read", "notes:write"],
      })
    ).status,
  ).toBe(201);
});

afterEach(async () => {
  await handle.dispose();
  await service.close();
  rmSync(directory, { recursive: true, force: true });
});

test("the signed-in owner continues to the app with a domain-wide forward cookie that yields resource tokens", async () => {
  const proceed = await continueTo(page);
  expect(proceed.status, await proceed.clone().text()).toBe(302);
  expect(proceed.headers.get("location")).toBe(page);

  const set = proceed.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith(`${forwardCookie}=`))!;

  expect(set).toContain("Domain=home.example");
  expect(set).toContain("HttpOnly");
  expect(set).toContain("Secure");
  expect(set).toContain("SameSite=Lax");
  expect(set).not.toContain("Max-Age");
  const forwarded = cookiePair(proceed, forwardCookie)!;

  // The app never sees the session cookie value, and cannot derive it.
  for (const pair of session.split("; ")) expect(forwarded).not.toContain(pair.split("=")[1]!);

  const response = await forward(forwarded);
  expect(response.status, await response.clone().text()).toBe(204);
  expect(response.headers.get("cache-control")).toBe("no-store");
  const authorization = response.headers.get("authorization") ?? "";
  expect(authorization).toMatch(/^Bearer /u);
  const keys = createLocalJWKSet(await (await call("/api/auth/jwks")).json());

  const { payload, protectedHeader } = await jwtVerify(authorization.slice(7), keys, {
    issuer: `${origin}/api/auth`,
    audience: resource,
    typ: "at+jwt",
  });

  expect(protectedHeader.alg).toBe("EdDSA");
  expect(payload.sub).toBe(await Effect.runPromise(service.owner()));
  expect(payload.client_id).toBe(forwardClientId);
  expect(payload.scope).toBe("notes:read notes:write");
  expect(payload.exp! - payload.iat!).toBe(15 * 60);
  // Bearer requests such as MCP clients and API keys bypass forward auth at the proxy;
  // the issuer itself never accepts these tokens for administration.
  expect(
    (await call("/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list" }, { authorization })).status,
  ).toBe(401);
});

test("without a forward cookie the browser passes through the issuer, which asks for login only without a session", async () => {
  redirectTo(await forward(""), "/forward-auth/continue");
  // The issuer session cookie alone does not count: apps only ever hold the forward cookie.
  redirectTo(await forward(session), "/forward-auth/continue");
  redirectTo(await forward(`${forwardCookie}=tampered`), "/forward-auth/continue");
  redirectTo(await continueTo(page, ""), "/login", continueURL());

  // A script's request cannot follow the issuer across origins, so it is refused in place.
  const scripted = await forward("", resource, page, "cors");
  expect(scripted.status).toBe(401);
  expect((await scripted.json()).error).toBe("unauthenticated");
});

test("proxy misconfiguration is refused: missing headers, foreign hosts, unknown or reserved resources", async () => {
  const bare = await handle(
    new Request(`${origin}/forward-auth?resource=${encodeURIComponent(resource)}`, {
      headers: { cookie: session },
    }),
  );

  expect(bare.status).toBe(400);
  expect((await bare.json()).error).toBe("invalid_forwarded_request");

  for (const original of [
    "https://notes.other.example/",
    "https://home.example.evil/",
    "http://notes.home.example/",
  ]) {
    const response = await forward(session, resource, original);
    expect(response.status, original).toBe(400);
    expect((await response.json()).error).toBe("invalid_forwarded_request");
  }

  for (const target of ["https://unknown.home.example/api", `${origin}/mcp`]) {
    const response = await forward(session, target);
    expect(response.status, target).toBe(403);
    expect((await response.json()).error).toBe("unknown_resource");
  }

  const elsewhere = await continueTo("https://evil.example/");
  expect(elsewhere.status).toBe(400);
  expect((await elsewhere.json()).error).toBe("invalid_return_url");
});

test("logout ends the session, clears both cookies, and revokes forward cookies already handed out", async () => {
  const forwarded = cookiePair(await continueTo(page), forwardCookie)!;
  expect((await forward(forwarded)).status).toBe(204);

  const logout = await call(
    "/forward-auth/logout?rd=https%3A%2F%2Fnotes.home.example%2F",
    undefined,
    {
      cookie: `${session}; ${forwarded}`,
    },
  );

  expect(logout.status).toBe(302);
  expect(logout.headers.get("location")).toBe("https://notes.home.example/");
  const cleared = logout.headers.getSetCookie();
  expect(
    cleared.some(
      (cookie) => cookie.startsWith(`${forwardCookie}=`) && cookie.includes("Max-Age=0"),
    ),
  ).toBe(true);
  expect(
    cleared.some(
      (cookie) => cookie.includes("session_token=") && /Max-Age=0|Expires=/u.test(cookie),
    ),
  ).toBe(true);
  // The forward cookie resolved to the deleted session, so a copy an app kept is dead too.
  redirectTo(await forward(forwarded), "/forward-auth/continue");

  const anonymous = await call("/forward-auth/logout?rd=https%3A%2F%2Fevil.example%2F", undefined, {
    cookie: "",
  });

  expect(anonymous.status).toBe(302);
  expect(anonymous.headers.get("location")).toBe(`${origin}/login`);
});
