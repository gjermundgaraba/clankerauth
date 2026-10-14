import { it } from "@effect/vitest";
import { expect } from "vite-plus/test";
import { Context, Effect, Layer, Schema } from "effect";
import { createLocalJWKSet, jwtVerify } from "jose";
import { forwardClientId, forwardCookie } from "../../src/forward-auth/forward-auth.ts";
import { testWebApplication, WebApplication } from "../test-issuer.ts";
import { OwnerAccount } from "../../src/owner/owner.ts";

const origin = "https://clankerauth.home.example";

const resource = "https://notes.home.example/api";

const page = "https://notes.home.example/docs?x=1";

const owner = { email: "owner@example.internal", password: "test-only password123" };

class Session extends Context.Service<Session, string>()("forward-auth.test/Session") {}

const handled = (request: Request) =>
  Effect.flatMap(WebApplication, (handle) => Effect.promise(() => handle(request)));

const send = (
  session: string,
  path: string,
  body?: typeof Schema.Json.Type,
  headers: Record<string, string> = {},
) =>
  handled(
    new Request(`${origin}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { origin, cookie: session, "content-type": "application/json", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
    }),
  );

const call = (path: string, body?: typeof Schema.Json.Type, headers: Record<string, string> = {}) =>
  Effect.flatMap(Session, (session) => send(session, path, body, headers));

const json = (response: Response) => Effect.promise(() => response.json());

const text = (response: Response) => Effect.promise(() => response.clone().text());

const continueTo = (rd: string, cookie?: string) =>
  call(
    `/forward-auth/continue?rd=${encodeURIComponent(rd)}`,
    undefined,
    cookie === undefined ? {} : { cookie },
  );

const forward = (cookie: string, target = resource, original = page, mode = "navigate") => {
  const url = new URL(original);

  return handled(
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

const continueURL = (original = page) =>
  `${origin}/forward-auth/continue?rd=${encodeURIComponent(original)}`;

const signedInOwner = Layer.effect(
  Session,
  Effect.gen(function* () {
    yield* (yield* OwnerAccount).create(owner);
    const login = yield* send("", "/api/auth/sign-in/email", owner);
    expect(login.status).toBe(200);
    expect(login.headers.getSetCookie().join(";")).not.toContain("Domain=");

    const session = login.headers
      .getSetCookie()
      .map((part) => part.split(";")[0])
      .join("; ");

    expect(
      (yield* send(session, "/api/createResource", {
        identifier: resource,
        name: "Notes",
        scopes: ["notes:read", "notes:write"],
      })).status,
    ).toBe(201);

    return session;
  }),
);

const forwardAuthIssuer = () =>
  signedInOwner.pipe(
    Layer.provideMerge(testWebApplication({ baseURL: origin, cookieDomain: "home.example" })),
  );

it.live(
  "the signed-in owner continues to the app with a domain-wide forward cookie that yields resource tokens",
  () =>
    Effect.gen(function* () {
      const session = yield* Session;
      const proceed = yield* continueTo(page);
      expect(proceed.status, yield* text(proceed)).toBe(302);
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

      for (const pair of session.split("; ")) expect(forwarded).not.toContain(pair.split("=")[1]!);

      const response = yield* forward(forwarded);
      expect(response.status, yield* text(response)).toBe(204);
      expect(response.headers.get("cache-control")).toBe("no-store");
      const authorization = response.headers.get("authorization") ?? "";
      expect(authorization).toMatch(/^Bearer /u);
      const keys = createLocalJWKSet(yield* json(yield* call("/api/auth/jwks")));

      const { payload, protectedHeader } = yield* Effect.promise(() =>
        jwtVerify(authorization.slice(7), keys, {
          issuer: `${origin}/api/auth`,
          audience: resource,
          typ: "at+jwt",
        }),
      );

      expect(protectedHeader.alg).toBe("EdDSA");
      expect(payload.sub).toBe(yield* (yield* OwnerAccount).find());
      expect(payload.client_id).toBe(forwardClientId);
      expect(payload.scope).toBe("notes:read notes:write");
      expect(payload.exp! - payload.iat!).toBe(15 * 60);
      expect(
        (yield* call("/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list" }, { authorization }))
          .status,
      ).toBe(401);
    }).pipe(Effect.provide(forwardAuthIssuer())),
);

it.live(
  "without a forward cookie the browser passes through the issuer, which asks for login only without a session",
  () =>
    Effect.gen(function* () {
      redirectTo(yield* forward(""), "/forward-auth/continue");
      redirectTo(yield* forward(yield* Session), "/forward-auth/continue");
      redirectTo(yield* forward(`${forwardCookie}=tampered`), "/forward-auth/continue");
      redirectTo(yield* continueTo(page, ""), "/login", continueURL());

      const scripted = yield* forward("", resource, page, "cors");
      expect(scripted.status).toBe(401);
      expect((yield* json(scripted)).error).toBe("unauthenticated");
    }).pipe(Effect.provide(forwardAuthIssuer())),
);

it.live(
  "proxy misconfiguration is refused: missing headers, foreign hosts, unknown or reserved resources",
  () =>
    Effect.gen(function* () {
      const session = yield* Session;

      const bare = yield* handled(
        new Request(`${origin}/forward-auth?resource=${encodeURIComponent(resource)}`, {
          headers: { cookie: session },
        }),
      );

      expect(bare.status).toBe(400);
      expect((yield* json(bare)).error).toBe("invalid_forwarded_request");

      for (const original of [
        "https://notes.other.example/",
        "https://home.example.evil/",
        "http://notes.home.example/",
      ]) {
        const response = yield* forward(session, resource, original);
        expect(response.status, original).toBe(400);
        expect((yield* json(response)).error).toBe("invalid_forwarded_request");
      }

      for (const target of ["https://unknown.home.example/api", `${origin}/`]) {
        const response = yield* forward(session, target);
        expect(response.status, target).toBe(403);
        expect((yield* json(response)).error).toBe("unknown_resource");
      }

      const elsewhere = yield* continueTo("https://evil.example/");
      expect(elsewhere.status).toBe(400);
      expect((yield* json(elsewhere)).error).toBe("invalid_return_url");
    }).pipe(Effect.provide(forwardAuthIssuer())),
);

it.live(
  "logout ends the session, clears both cookies, and revokes forward cookies already handed out",
  () =>
    Effect.gen(function* () {
      const session = yield* Session;
      const forwarded = cookiePair(yield* continueTo(page), forwardCookie)!;
      expect((yield* forward(forwarded)).status).toBe(204);

      const logout = yield* call(
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
      redirectTo(yield* forward(forwarded), "/forward-auth/continue");

      const anonymous = yield* call(
        "/forward-auth/logout?rd=https%3A%2F%2Fevil.example%2F",
        undefined,
        {
          cookie: "",
        },
      );

      expect(anonymous.status).toBe(302);
      expect(anonymous.headers.get("location")).toBe(`${origin}/login`);
    }).pipe(Effect.provide(forwardAuthIssuer())),
);
