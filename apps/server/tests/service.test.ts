import { it } from "@effect/vitest";
import { Context, Effect, Layer, Schema } from "effect";
import { documentPaths } from "@clankerauth/web/document-paths";
import { InternalServerError } from "@gjermundgaraba/clankerauth-admin-api";
import { sql as query } from "kysely";
import { describe, expect } from "vite-plus/test";
import { createHash, randomBytes } from "node:crypto";
import { createLocalJWKSet, jwtVerify } from "jose";
import {
  advanceDate,
  cookieJar,
  issuerGeneration,
  testSettings,
  WebApplication,
} from "./test-issuer.ts";
import { peerHeader } from "../src/platform/node-http.ts";

import { administrationResource } from "./mcp-oauth-helper.ts";
import { Database } from "../src/platform/sqlite.ts";
import { OwnerAccount } from "../src/owner/owner.ts";
import { Issuer, refreshTokenReuseSeconds } from "../src/issuer/issuer.ts";
import { ResourceCatalog } from "../src/resources/catalog.ts";

const FormFields = Schema.Record(Schema.String, Schema.String);

type TestRequestBody = typeof Schema.JsonObject.Type;

const password = "test-only owner password 8rS!";

const email = "owner@example.internal";

const resourceA = "https://notes.internal/mcp";

const resourceB = "https://reports.internal/api";

const baseURL = "http://localhost:3000";

class CookieJar extends Context.Service<CookieJar, ReturnType<typeof cookieJar>>()(
  "service.test/CookieJar",
) {}

const generation = () => WebApplication.layer.pipe(Layer.provideMerge(issuerGeneration()));

const browser = () => Layer.merge(testSettings({ baseURL }), Layer.sync(CookieJar, cookieJar));

const onGeneration = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  Effect.provide(effect, generation());

const serviceIssuer = () => generation().pipe(Layer.provideMerge(browser()));

const sql = (strings: TemplateStringsArray, ...parameters: readonly unknown[]) =>
  Effect.flatMap(Database, (database) => database.sql(strings, ...parameters));

const json = (response: Response) => Effect.promise(() => response.json());

const text = (response: Response) => Effect.promise(() => response.clone().text());

const request = (
  path: string,
  body?: TestRequestBody,
  options: { anonymous?: boolean; form?: boolean; origin?: string; authorization?: string } = {},
) =>
  Effect.gen(function* () {
    const handle = yield* WebApplication;
    const cookies = yield* CookieJar;

    const headers = new Headers({
      origin: options.origin ?? baseURL,
      [peerHeader]: "127.0.0.1",
    });

    if (options.authorization) headers.set("authorization", options.authorization);

    if (!options.anonymous) headers.set("cookie", cookies.header());

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

    const response = yield* Effect.promise(() =>
      handle(
        new Request(new URL(path, baseURL), {
          method: body ? "POST" : "GET",
          headers,
          body: encoded,
        }),
      ),
    );

    if (!options.anonymous) cookies.keep(response);

    return response;
  });

const login = (pass = password) => request("/api/auth/sign-in/email", { email, password: pass });

const resourceFixtures = [
  { identifier: resourceA, name: "Notes MCP", scopes: ["notes:read", "notes:write"] },
  { identifier: resourceB, name: "Reports", scopes: ["reports:read"] },
];

const putResourceFixtures = Effect.gen(function* () {
  const listing = yield* json(yield* request("/api/listClients", {}));

  for (const resource of resourceFixtures) {
    if (
      listing.resources.some(
        (row: { identifier: string }) => row.identifier === resource.identifier,
      )
    )
      continue;
    const response = yield* request("/api/putResource", resource);
    expect(response.status, yield* text(response)).toBe(200);
  }
});

const client = (resource = resourceA, confidential = false) =>
  Effect.gen(function* () {
    yield* putResourceFixtures;

    const response = yield* request("/api/createClient", {
      client_name: "Test application",
      redirect_uris: ["http://127.0.0.1:9876/callback"],
      resources: [resource],
      application_type: "native",
      token_endpoint_auth_method: confidential ? "client_secret_basic" : "none",
    });

    expect(response.status, yield* text(response)).toBe(201);

    return yield* json(response);
  });

const dynamicClient = Effect.gen(function* () {
  yield* putResourceFixtures;

  const response = yield* request(
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

  expect(response.status, yield* text(response)).toBe(201);

  return yield* json(response);
});

function unprompted(clientId: string, resource = resourceA, extra: Record<string, string> = {}) {
  const flow = authorization(clientId, resource, extra);
  const url = new URL(flow.path, baseURL);
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

const authorize = (clientId: string, resource = resourceA, scope?: string) =>
  Effect.gen(function* () {
    const flow = authorization(
      clientId,
      resource,
      scope ? { scope } : resource === resourceB ? { scope: "offline_access reports:read" } : {},
    );

    const response = yield* request(flow.path);
    expect(response.status, yield* text(response)).toBe(302);
    const location = new URL(response.headers.get("location")!, baseURL);
    expect(location.pathname).toBe("/consent");

    const result = yield* request("/api/auth/oauth2/consent", {
      accept: true,
      oauth_query: location.search.slice(1),
    });

    expect(result.status, yield* text(result)).toBe(200);
    const redirect = new URL((yield* json(result)).url);
    expect(redirect.searchParams.get("state")).toBe("state-to-validate");
    expect(redirect.searchParams.get("iss")).toBe(`${baseURL}/api/auth`);

    return { code: redirect.searchParams.get("code")!, verifier: flow.verifier };
  });

const tokens = (clientId: string, resource = resourceA, authorization?: string, scope?: string) =>
  Effect.gen(function* () {
    const grant = yield* authorize(clientId, resource, scope);

    const response = yield* request(
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

    expect(response.status, yield* text(response)).toBe(200);

    return yield* json(response);
  });

const setupOwner = Effect.gen(function* () {
  const response = yield* request("/api/setupOwner", { email, password });
  expect(response.status, yield* text(response)).toBe(201);
});

const ownerIssuer = () => Layer.effectDiscard(setupOwner).pipe(Layer.provideMerge(serviceIssuer()));

const signedInOwner = Effect.gen(function* () {
  yield* setupOwner;
  expect((yield* login()).status).toBe(200);
});

const signedInIssuer = () =>
  Layer.effectDiscard(signedInOwner).pipe(Layer.provideMerge(serviceIssuer()));

const rejection = <A>(evaluate: () => Promise<A>) =>
  Effect.flip(Effect.tryPromise({ try: evaluate, catch: (error) => error }));

describe("first-run setup", () => {
  it.live(
    "fresh startup and restart permit setup, which signs the owner in and closes permanently",
    () =>
      Effect.gen(function* () {
        yield* onGeneration(
          Effect.gen(function* () {
            expect(yield* json(yield* request("/api/setupStatus", {}))).toEqual({
              required: true,
            });
          }),
        );

        const owner = yield* onGeneration(
          Effect.gen(function* () {
            const status = yield* request("/api/setupStatus", {});
            expect(yield* json(status)).toEqual({ required: true });
            expect(status.headers.get("cache-control")).toContain("no-store");
            expect((yield* request("/api/listClients", {})).status).toBe(401);
            expect(
              (yield* request("/api/auth/sign-up/email", { email, password, name: "Owner" }))
                .status,
            ).toBe(404);

            const created = yield* request("/api/setupOwner", {
              email: "Owner@Example.Internal",
              password,
            });

            expect(created.status, yield* text(created)).toBe(201);
            expect(yield* json(created)).toEqual({ created: true });
            expect(
              created.headers
                .getSetCookie()
                .find((cookie) => cookie.startsWith("better-auth.session_token=")),
            ).not.toMatch(/;\s*Secure/iu);
            expect(created.headers.getSetCookie().join(";")).toContain("HttpOnly");
            expect((yield* sql`SELECT count(*) AS n FROM session`)[0]).toEqual({
              n: 1,
            });
            expect((yield* sql`SELECT name, email, emailVerified FROM user`)[0]).toEqual({
              name: "Owner",
              email,
              emailVerified: 0,
            });
            const owner = yield* (yield* OwnerAccount).find();
            expect(owner).toBeTypeOf("string");
            expect(yield* json(yield* request("/api/setupStatus", {}))).toEqual({
              required: false,
            });
            expect((yield* request("/api/listClients", {})).status).toBe(200);
            expect((yield* request("/api/listClients", {}, { anonymous: true })).status).toBe(401);
            expect((yield* login()).status).toBe(200);

            return owner;
          }),
        );

        yield* onGeneration(
          Effect.gen(function* () {
            expect(yield* (yield* OwnerAccount).find()).toBe(owner);
            expect(yield* json(yield* request("/api/setupStatus", {}))).toEqual({
              required: false,
            });
            expect((yield* request("/api/listClients", {})).status).toBe(200);
            expect((yield* request("/api/setupOwner", { email, password })).status).toBe(409);
            const { auth } = yield* Issuer;
            expect(
              yield* rejection(() =>
                auth.api.signUpEmail({
                  body: { email: "second@example.internal", password, name: "Owner" },
                }),
              ),
            ).toMatchObject({ statusCode: 409, message: "Setup already completed" });
            expect((yield* sql`SELECT count(*) AS n FROM user`)[0]).toEqual({
              n: 1,
            });
          }),
        );
      }).pipe(Effect.provide(browser())),
  );

  it.live("invalid setup input and encoding never create an account", () =>
    Effect.gen(function* () {
      const handle = yield* WebApplication;

      for (const body of [
        { email: "invalid", password },
        { email: ".owner@example.internal", password },
        { email: "owner..name@example.internal", password },
        { email: "owner@example.123", password },
        { email, password: "x".repeat(7) },
        { email, password: "x".repeat(129) },
      ]) {
        const response = yield* Effect.promise(() =>
          handle(
            new Request(`${baseURL}/api/setupOwner`, {
              method: "POST",
              headers: { origin: baseURL, "content-type": "application/json" },
              body: JSON.stringify(body),
            }),
          ),
        );

        expect(response.status, yield* text(response)).toBe(400);
      }

      for (const [contentType, body] of [
        ["application/json", "{"],
        ["text/plain", JSON.stringify({ email, password })],
        ["application/x-www-form-urlencoded", new URLSearchParams({ email, password }).toString()],
      ]) {
        const response = yield* Effect.promise(() =>
          handle(
            new Request(`${baseURL}/api/setupOwner`, {
              method: "POST",
              headers: { origin: baseURL, "content-type": contentType! },
              body,
            }),
          ),
        );

        // why: the library's status for an unparseable encoding varies; any 4xx is a refusal
        expect(response.status, contentType).toBeGreaterThanOrEqual(400);
        expect(response.status, contentType).toBeLessThan(500);
        expect(yield* text(response)).not.toContain(password);
      }

      expect((yield* sql`SELECT count(*) AS n FROM user`)[0]).toEqual({
        n: 0,
      });
      expect(yield* (yield* OwnerAccount).find()).toBeUndefined();
      yield* setupOwner;
    }).pipe(Effect.provide(serviceIssuer())),
  );

  it.live.each([
    "  Owner+Tag@Example.Internal  ",
    "owner'name@example.internal",
    `${"a".repeat(237)}@example.internal`,
  ])("setup email %s remains usable for provider login", (input) =>
    Effect.gen(function* () {
      const response = yield* request("/api/setupOwner", { email: input, password });
      expect(response.status).toBe(201);
      const normalized = input.trim().toLowerCase();
      expect((yield* sql`SELECT email FROM user`)[0]).toEqual({
        email: normalized,
      });
      expect(
        (yield* request("/api/auth/sign-in/email", { email: normalized, password })).status,
      ).toBe(200);
    }).pipe(Effect.provide(serviceIssuer())),
  );

  it.live("simultaneous submissions create exactly one owner", () =>
    Effect.gen(function* () {
      const responses = yield* Effect.all(
        [
          request("/api/setupOwner", { email, password }),
          request("/api/setupOwner", { email: "second@example.internal", password }),
        ],
        { concurrency: "unbounded" },
      );

      expect(responses.map((response) => response.status).sort((a, b) => a - b)).toEqual([
        201, 409,
      ]);

      for (const table of ["user", "account", "session"])
        expect((yield* sql`SELECT count(*) AS n FROM ${query.table(table)}`)[0]).toEqual({ n: 1 });
    }).pipe(Effect.provide(serviceIssuer())),
  );

  it.live("simultaneous submissions with the same email report the loser as a conflict", () =>
    Effect.gen(function* () {
      const responses = yield* Effect.all(
        [
          request("/api/setupOwner", { email, password }),
          request("/api/setupOwner", { email, password: `${password} other` }),
        ],
        { concurrency: "unbounded" },
      );

      expect(responses.map((response) => response.status).sort((a, b) => a - b)).toEqual([
        201, 409,
      ]);
      expect((yield* sql`SELECT count(*) AS n FROM user`)[0]).toEqual({
        n: 1,
      });
    }).pipe(Effect.provide(serviceIssuer())),
  );

  it.live("a failed credential insert rolls back the account and permits retry", () =>
    Effect.gen(function* () {
      yield* sql`CREATE TRIGGER fail_setup BEFORE INSERT ON account
      BEGIN SELECT RAISE(ABORT, 'Injected credential failure'); END`;
      const failed = yield* request("/api/setupOwner", { email, password });
      expect(failed.status).toBe(500);
      const error = yield* text(failed);
      expect(error).not.toContain(password);
      expect(error).not.toContain("Injected credential failure");

      for (const table of ["user", "account", "session"])
        expect((yield* sql`SELECT count(*) AS n FROM ${query.table(table)}`)[0]).toEqual({ n: 0 });
      expect(yield* json(yield* request("/api/setupStatus", {}))).toEqual({
        required: true,
      });
      yield* sql`DROP TRIGGER fail_setup`;
      yield* setupOwner;
      expect((yield* login()).status).toBe(200);
    }).pipe(Effect.provide(serviceIssuer())),
  );
});

describe("owner boundary", () => {
  it.live("serves the built web workspace rather than the server working directory", () =>
    Effect.gen(function* () {
      const assets = new Set<string>();

      for (const path of documentPaths) {
        const response = yield* request(path);
        expect(response.status).toBe(200);
        expect(response.headers.get("content-type")).toContain("text/html");
        const html = yield* text(response);
        expect(html).toContain("<title>clankerauth</title>");
        const references = [...html.matchAll(/(?:src|href)="(\/assets\/[^" ]+)"/g)];
        expect(references.length).toBeGreaterThan(0);

        for (const reference of references) assets.add(reference[1]!);
      }

      const fonts = new Set<string>();

      for (const asset of assets) {
        const result = yield* request(asset);
        expect(result.status).toBe(200);
        expect(result.headers.get("content-type")).toBe(
          asset.endsWith(".js") ? "text/javascript" : "text/css",
        );
        const body = yield* text(result);
        expect(body).not.toBe("");

        for (const font of body.matchAll(/url\((\/assets\/[^)]+\.woff2)\)/g)) fonts.add(font[1]!);
      }

      expect(fonts.size).toBeGreaterThan(0);

      for (const font of fonts) {
        const result = yield* request(font);
        expect(result.status).toBe(200);
        expect(result.headers.get("content-type")).toBe("font/woff2");
      }

      expect((yield* request("/src/main.ts")).status).toBe(404);
    }).pipe(Effect.provide(ownerIssuer())),
  );

  it.live("login throttles brute force without exposing passwords", () =>
    Effect.gen(function* () {
      for (let i = 0; i < 5; i++) expect((yield* login("deliberately incorrect")).status).toBe(401);
      const limited = yield* login();
      expect(limited.status).toBe(429);
      expect(yield* text(limited)).not.toContain(password);
    }).pipe(Effect.provide(ownerIssuer())),
  );

  it.live("closed signup, protected admin, SameSite cookies, credential login and logout", () =>
    Effect.gen(function* () {
      expect((yield* request("/api/listClients", {}, { anonymous: true })).status).toBe(401);
      expect(
        (yield* request("/api/auth/sign-up/email", {
          email: "stranger@example.internal",
          password,
          name: "Intruder",
        })).status,
      ).toBe(404);
      const { auth } = yield* Issuer;
      expect(
        yield* rejection(() =>
          auth.api.signUpEmail({
            body: { email: "stranger@example.internal", password, name: "Intruder" },
          }),
        ),
      ).toMatchObject({ statusCode: 409 });
      expect((yield* login("incorrect password")).status).toBe(401);
      const signedIn = yield* login();
      expect(signedIn.status).toBe(200);
      expect(signedIn.headers.getSetCookie().join(";")).toContain("HttpOnly");
      expect(signedIn.headers.getSetCookie().join(";")).toContain("SameSite=Lax");
      const session = yield* request("/api/auth/get-session");
      expect(session.status).toBe(200);
      const current = yield* json(session);
      expect(current.user.id).toBe(yield* (yield* OwnerAccount).find());
      expect(session.headers.has("set-auth-jwt")).toBe(false);
      expect((yield* request("/api/listClients", {})).status).toBe(200);
      expect(
        (yield* request("/api/auth/oauth2/create-client", {
          redirect_uris: ["https://evil.example"],
        })).status,
      ).toBe(404);
      expect((yield* request("/api/auth/token")).status).toBe(404);
      expect((yield* request("/api/auth/sign-out", {})).status).toBe(200);
      expect((yield* request("/api/listClients", {})).status).toBe(401);
    }).pipe(Effect.provide(ownerIssuer())),
  );
});

describe("OAuth boundaries and lifecycle", () => {
  it.live(
    "the owner's session is the single sign-on session: 30 days, renewed by application sign-in",
    () =>
      Effect.gen(function* () {
        const day = 24 * 60 * 60 * 1000;

        const expiry = () =>
          Effect.gen(function* () {
            const response = yield* request("/api/auth/get-session");
            expect(response.status).toBe(200);

            return Date.parse((yield* json(response)).session.expiresAt);
          });

        yield* login();
        const app = yield* client();
        const initial = yield* expiry();
        expect(initial - Date.now()).toBeGreaterThan(29 * day);
        expect(initial - Date.now()).toBeLessThanOrEqual(30 * day);

        yield* Effect.scoped(
          Effect.gen(function* () {
            yield* advanceDate(2 * day);
            const redirect = yield* request(unprompted(app.client_id).path);
            expect(redirect.status, yield* text(redirect)).toBe(302);
            expect(redirect.headers.getSetCookie().join(";")).toContain("session_token");
            const renewed = yield* expiry();
            expect(renewed).toBeGreaterThan(initial + day);
            expect(renewed - Date.now()).toBeLessThanOrEqual(30 * day);
          }),
        );
      }).pipe(Effect.provide(ownerIssuer())),
  );

  it.live("managed clients are first party: a signed-in owner is redirected without consent", () =>
    Effect.gen(function* () {
      yield* login();
      const app = yield* client();
      const flow = unprompted(app.client_id);
      const response = yield* request(flow.path);
      expect(response.status, yield* text(response)).toBe(302);
      const redirect = new URL(response.headers.get("location")!);
      expect(`${redirect.origin}${redirect.pathname}`).toBe("http://127.0.0.1:9876/callback");
      expect(redirect.searchParams.get("state")).toBe("state-to-validate");
      expect(yield* sql`SELECT id FROM oauthConsent WHERE clientId = ${app.client_id}`).toEqual([]);

      const issued = yield* request(
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

      expect(issued.status, yield* text(issued)).toBe(200);
      expect((yield* json(issued)).scope.split(" ")).toContain("notes:read");
      const prompted = yield* request(authorization(app.client_id).path);
      expect(new URL(prompted.headers.get("location")!, baseURL).pathname).toBe("/consent");
      const dynamic = yield* dynamicClient;
      const asked = yield* request(unprompted(dynamic.client_id).path);
      expect(new URL(asked.headers.get("location")!, baseURL).pathname).toBe("/consent");
    }).pipe(Effect.provide(ownerIssuer())),
  );

  it.live(
    "confidential Basic authentication, rotation, introspection, logout and client deletion",
    () =>
      Effect.gen(function* () {
        yield* login();
        const app = yield* client(resourceA, true);
        expect(app.client_secret).toBeTypeOf("string");
        const listing = yield* json(yield* request("/api/listClients", {}));
        expect(JSON.stringify(listing)).not.toContain(app.client_secret);
        const grant = yield* authorize(app.client_id);

        const basic = (secret: string) =>
          `Basic ${Buffer.from(`${app.client_id}:${secret}`).toString("base64")}`;

        const exchange = yield* request(
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

        expect(exchange.status, yield* text(exchange)).toBe(200);
        expect(exchange.headers.get("access-control-allow-origin")).toBe("*");
        const issued = yield* json(exchange);

        const introspect = (secret: string) =>
          request(
            "/api/auth/oauth2/introspect",
            { token: issued.access_token },
            { anonymous: true, form: true, authorization: basic(secret) },
          );

        expect((yield* json(yield* introspect(app.client_secret))).active).toBe(true);

        const rotated = yield* json(
          yield* request("/api/rotateClientSecret", { client_id: app.client_id }),
        );

        expect(rotated.client_secret).toBeTypeOf("string");
        expect(rotated.client_secret).not.toBe(app.client_secret);
        expect((yield* introspect(app.client_secret)).status).toBe(401);
        expect((yield* json(yield* introspect(rotated.client_secret))).active).toBe(true);
        yield* request("/api/auth/sign-out", {});
        expect((yield* json(yield* introspect(rotated.client_secret))).active).toBe(false);
        yield* login();
        expect((yield* request("/api/deleteClient", { client_id: app.client_id })).status).toBe(
          200,
        );
        expect((yield* json(yield* request("/api/listClients", {}))).clients).toEqual([]);

        const refresh = yield* request(
          "/api/auth/oauth2/token",
          {
            grant_type: "refresh_token",
            client_id: app.client_id,
            refresh_token: issued.refresh_token,
            resource: resourceA,
          },
          { anonymous: true, form: true, authorization: basic(rotated.client_secret) },
        );

        expect(refresh.status, yield* text(refresh)).toBe(401);
        expect((yield* json(refresh)).error).toBe("invalid_client");
      }).pipe(Effect.provide(ownerIssuer())),
  );

  it.live(
    "discovery pins issuer and advertises S256 and automatic onboarding without machine grants",
    () =>
      Effect.gen(function* () {
        for (const path of [
          "/.well-known/oauth-authorization-server/api/auth",
          "/api/auth/.well-known/oauth-authorization-server",
        ]) {
          const response = yield* request(path);
          expect(response.status, yield* text(response)).toBe(200);
          const metadata = yield* json(response);
          expect(metadata.issuer).toBe(`${baseURL}/api/auth`);
          expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
          expect(metadata.registration_endpoint).toBe(`${baseURL}/api/auth/oauth2/register`);
          expect(metadata.client_id_metadata_document_supported).toBe(true);
          expect(metadata.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
        }
      }).pipe(Effect.provide(ownerIssuer())),
  );

  it.live("scopes no resource defines are refused before consent", () =>
    Effect.gen(function* () {
      yield* login();
      const app = yield* client();

      const response = yield* request(
        authorization(app.client_id, resourceA, { scope: "notes:read notes:nope" }).path,
      );

      expect(response.status, yield* text(response)).toBe(302);
      const location = new URL(response.headers.get("location")!);
      expect(location.origin + location.pathname).toBe("http://127.0.0.1:9876/callback");
      expect(location.searchParams.get("error")).toBe("invalid_scope");
    }).pipe(Effect.provide(ownerIssuer())),
  );

  it.live("login continuation and signed consent denial; altered consent is rejected", () =>
    Effect.gen(function* () {
      yield* login();
      const app = yield* client();
      (yield* CookieJar).clear();
      const flow = authorization(app.client_id);
      const response = yield* request(flow.path);
      const location = new URL(response.headers.get("location")!, baseURL);
      expect(location.pathname).toBe("/login");

      const signedIn = yield* request("/api/auth/sign-in/email", {
        email,
        password,
        oauth_query: location.search.slice(1),
      });

      expect(signedIn.status, yield* text(signedIn)).toBe(200);
      const continued = new URL((yield* json(signedIn)).url, baseURL);
      expect(continued.pathname).toBe("/consent");
      const tampered = new URL(continued);
      tampered.searchParams.set("resource", resourceB);
      expect(
        (yield* request("/api/auth/oauth2/consent", {
          accept: true,
          oauth_query: tampered.search.slice(1),
        })).status,
      ).toBe(400);

      const denied = yield* request("/api/auth/oauth2/consent", {
        accept: false,
        oauth_query: continued.search.slice(1),
      });

      expect(denied.status).toBe(200);
      const result = new URL((yield* json(denied)).url);
      expect(result.searchParams.get("error")).toBe("access_denied");
      expect(result.searchParams.get("code")).toBeNull();
    }).pipe(Effect.provide(ownerIssuer())),
  );

  it.live(
    "S256, redirect matching, single-resource authorization and per-client audience enforcement",
    () =>
      Effect.gen(function* () {
        yield* login();
        const app = yield* client();

        const invalidRequests: Record<string, string>[] = [
          { code_challenge_method: "plain" },
          { redirect_uri: "http://127.0.0.1:9876/evil" },
          { resource: "" },
        ];

        for (const extra of invalidRequests) {
          const response = yield* request(authorization(app.client_id, resourceA, extra).path);
          const body = yield* text(response);
          expect(
            response.status >= 400 || response.headers.get("location")?.includes("error="),
            body,
          ).toBeTruthy();
        }

        const multiple = yield* request(
          `${authorization(app.client_id).path}&resource=${encodeURIComponent(resourceB)}`,
        );

        expect((yield* json(multiple)).error).toBe("invalid_target");

        const unallowed = yield* request(
          authorization(app.client_id, resourceB, { prompt: "none" }).path,
        );

        expect(unallowed.status).toBe(400);
        expect(yield* json(unallowed)).toMatchObject({
          error: "invalid_target",
          error_description: "Client access is required",
        });

        const forced = yield* request(authorization(app.client_id, resourceB).path);
        const consentQuery = new URL(forced.headers.get("location")!, baseURL).search;

        const refused = yield* request("/api/auth/oauth2/consent", {
          accept: true,
          oauth_query: consentQuery.slice(1),
        });

        expect((yield* json(refused)).error).toBe("invalid_target");
        const grant = yield* authorize(app.client_id);

        const wrongVerifier = yield* request(
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

        expect(wrongVerifier.status).toBe(400);
        expect((yield* json(wrongVerifier)).error).toBe("invalid_grant");
      }).pipe(Effect.provide(ownerIssuer())),
  );

  it.live("issued JWT claims and signing keys remain valid across restart", () =>
    Effect.gen(function* () {
      const { a, tokenA, jwks } = yield* onGeneration(
        Effect.gen(function* () {
          yield* setupOwner;
          yield* login();
          const a = yield* client();
          const b = yield* client(resourceB);
          const tokenA = yield* tokens(a.client_id);
          const tokenB = yield* tokens(b.client_id, resourceB);
          const jwks = yield* json(yield* request("/api/auth/jwks"));
          const keys = createLocalJWKSet(jwks);

          const verified = yield* Effect.promise(() =>
            jwtVerify(tokenA.access_token, keys, {
              issuer: `${baseURL}/api/auth`,
              audience: resourceA,
              typ: "at+jwt",
            }),
          );

          expect(verified.payload.aud).toEqual(resourceA);
          expect(verified.payload.scope).toContain("notes:read");
          expect(verified.payload.exp! - verified.payload.iat!).toBeLessThanOrEqual(900);

          const verifiedB = yield* Effect.promise(() =>
            jwtVerify(tokenB.access_token, keys, {
              issuer: `${baseURL}/api/auth`,
              audience: resourceB,
              typ: "at+jwt",
            }),
          );

          expect(verifiedB.payload.aud).not.toContain(resourceA);

          return { a, tokenA, jwks };
        }),
      );

      yield* onGeneration(
        Effect.gen(function* () {
          expect(yield* json(yield* request("/api/auth/jwks"))).toEqual(jwks);
          expect((yield* request("/api/listClients", {})).status).toBe(200);

          const refresh = yield* request(
            "/api/auth/oauth2/token",
            {
              grant_type: "refresh_token",
              client_id: a.client_id,
              refresh_token: tokenA.refresh_token,
              resource: resourceA,
            },
            { anonymous: true, form: true },
          );

          expect(refresh.status, yield* text(refresh)).toBe(200);
        }),
      );
    }).pipe(Effect.provide(browser())),
  );

  it.live(
    "refresh is resource-bound, rotates with a reuse window, detects replay, and revokes",
    () =>
      Effect.gen(function* () {
        yield* login();
        const app = yield* client();
        const original = yield* tokens(app.client_id);

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

        expect((yield* refresh(original.refresh_token, resourceB)).status).toBe(400);
        const rotatedResponse = yield* refresh(original.refresh_token, resourceA);
        expect(rotatedResponse.status, yield* text(rotatedResponse)).toBe(200);
        const rotated = yield* json(rotatedResponse);
        expect(rotated.refresh_token).not.toBe(original.refresh_token);
        const replayed = yield* refresh(original.refresh_token, resourceA);
        expect(replayed.status, yield* text(replayed)).toBe(200);
        expect((yield* json(replayed)).refresh_token).toBe(rotated.refresh_token);
        const bare = yield* refresh(rotated.refresh_token);
        expect(bare.status, yield* text(bare)).toBe(200);
        const next = yield* json(bare);
        const keys = createLocalJWKSet(yield* json(yield* request("/api/auth/jwks")));
        yield* Effect.promise(() => jwtVerify(next.access_token, keys, { audience: resourceA }));

        yield* Effect.scoped(
          Effect.gen(function* () {
            yield* advanceDate((refreshTokenReuseSeconds + 1) * 1000);
            expect((yield* refresh(rotated.refresh_token, resourceA)).status).toBe(400);
            expect((yield* refresh(next.refresh_token, resourceA)).status).toBe(400);
          }),
        );

        const another = yield* tokens(app.client_id);

        const revoked = yield* request(
          "/api/auth/oauth2/revoke",
          {
            token: another.refresh_token,
            token_type_hint: "refresh_token",
            client_id: app.client_id,
          },
          { form: true, anonymous: true },
        );

        expect(revoked.status).toBe(200);
        expect((yield* refresh(another.refresh_token)).status).toBe(400);

        const jwtRevocation = yield* request(
          "/api/auth/oauth2/revoke",
          {
            token: another.access_token,
            token_type_hint: "access_token",
            client_id: app.client_id,
          },
          { form: true, anonymous: true },
        );

        expect(jwtRevocation.status).toBe(400);
        expect((yield* json(jwtRevocation)).error).toBe("unsupported_token_type");
      }).pipe(Effect.provide(ownerIssuer())),
  );
});

describe("dashboard resources and client access", () => {
  const listing = () => Effect.flatMap(request("/api/listClients", {}), json);

  const access = (clientId: string, resources: string[]) =>
    request("/api/setClientAccess", { client_id: clientId, resources });

  const putResource = (identifier: string, scopes: string[], name = "Updated resource") =>
    request("/api/putResource", { identifier, name, scopes });

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

  it.live(
    "the built-in administration resource survives restart and user resource CRUD persists",
    () =>
      Effect.gen(function* () {
        yield* onGeneration(
          Effect.gen(function* () {
            yield* signedInOwner;
            expect((yield* listing()).resources).toEqual([administrationResource(baseURL)]);
          }),
        );

        const resource = { identifier: resourceA, name: "Personal MCP", scopes: ["read", "write"] };

        yield* onGeneration(
          Effect.gen(function* () {
            expect((yield* listing()).resources).toEqual([administrationResource(baseURL)]);
            expect(yield* json(yield* request("/api/putResource", resource))).toEqual({
              resource,
              created: true,
            });
            expect(yield* json(yield* request("/api/putResource", resource))).toEqual({
              resource,
              created: false,
            });
            expect((yield* putResource(resourceA, ["read"], "Renamed MCP")).status).toBe(200);
          }),
        );

        yield* onGeneration(
          Effect.gen(function* () {
            expect((yield* listing()).resources).toEqual([
              administrationResource(baseURL),
              { ...resource, name: "Renamed MCP", scopes: ["read"], builtIn: false },
            ]);
            expect((yield* request("/api/deleteResource", { identifier: resourceA })).status).toBe(
              200,
            );
          }),
        );

        yield* onGeneration(
          Effect.gen(function* () {
            expect((yield* listing()).resources).toEqual([administrationResource(baseURL)]);
            expect((yield* request("/api/getResource", { identifier: resourceA })).status).toBe(
              404,
            );
            expect((yield* request("/api/deleteResource", { identifier: resourceA })).status).toBe(
              404,
            );
          }),
        );
      }).pipe(Effect.provide(browser())),
  );

  it.live(
    "resource mutations reject invalid input and unauthorized requests but accept older valid sessions",
    () =>
      Effect.gen(function* () {
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
        ]) {
          expect((yield* request("/api/putResource", input)).status, JSON.stringify(input)).toBe(
            400,
          );
        }

        const fragment = yield* request("/api/putResource", {
          ...valid,
          identifier: "https://api.internal/#fragment",
        });

        expect((yield* json(fragment)).issues).toEqual([
          {
            path: ["identifier"],
            message:
              "Resource identifiers must be absolute URIs in canonical form, without a fragment",
          },
        ]);

        const reserved = yield* request("/api/putResource", {
          ...valid,
          scopes: ["read", " offline_access "],
        });

        expect((yield* json(reserved)).issues).toEqual([
          { path: ["scopes", 1], message: "offline_access is reserved" },
        ]);

        expect((yield* request("/api/putResource", valid, { anonymous: true })).status).toBe(401);
        expect((yield* listing()).resources).toEqual([administrationResource(baseURL)]);
        const { context } = yield* Issuer;
        const ownerId = yield* (yield* OwnerAccount).find();

        if (ownerId === undefined) return yield* Effect.die("Missing test owner");
        yield* Effect.promise(() =>
          context.adapter.update({
            model: "session",
            where: [{ field: "userId", value: ownerId }],
            update: { createdAt: new Date(Date.now() - 16 * 60_000) },
          }),
        );
        expect((yield* request("/api/putResource", valid)).status).toBe(200);
        expect((yield* listing()).resources).toEqual([
          administrationResource(baseURL),
          { ...valid, builtIn: false },
        ]);

        const created = yield* request("/api/createClient", {
          client_name: "Older session client",
          redirect_uris: ["http://127.0.0.1:9876/callback"],
          resources: [],
          application_type: "native",
          token_endpoint_auth_method: "client_secret_basic",
        });

        expect(created.status, yield* text(created)).toBe(201);
        const app = yield* json(created);
        expect(
          (yield* request("/api/rotateClientSecret", {
            client_id: app.client_id,
          })).status,
        ).toBe(200);
      }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live("domain refusals and internal failures share one wire vocabulary", () =>
    Effect.gen(function* () {
      const resource = { identifier: resourceA, name: "Notes MCP", scopes: ["notes:read"] };
      expect((yield* request("/api/putResource", resource)).status).toBe(200);

      const reserved = yield* request("/api/deleteResource", {
        identifier: `${baseURL}/`,
      });

      expect(reserved.status).toBe(400);
      const refused = yield* json(reserved);
      expect(refused._tag).toBe("InvalidInput");
      expect(refused.issues).toEqual([
        { path: ["identifier"], message: "The administration Resource is fixed" },
      ]);

      yield* sql`UPDATE oauthResource SET allowedScopes = 'not json' WHERE identifier = ${resourceA}`;

      const authorize = yield* request(
        `/api/auth/oauth2/authorize?client_id=unused&resource=${encodeURIComponent(resourceA)}`,
        undefined,
        { anonymous: true },
      );

      expect(authorize.status).toBe(500);
      expect(yield* json(authorize)).toEqual(
        Schema.encodeSync(InternalServerError)(
          new InternalServerError({ message: "Request could not be completed" }),
        ),
      );
    }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live("resources accept any absolute URI and may define no custom scopes", () =>
    Effect.gen(function* () {
      const urn = { identifier: "urn:example:reports", name: "Reports", scopes: [] };
      expect((yield* request("/api/putResource", urn)).status).toBe(200);
      expect((yield* listing()).resources).toEqual([
        administrationResource(baseURL),
        { ...urn, builtIn: false },
      ]);
      expect((yield* putResource(urn.identifier, [], "Renamed reports")).status).toBe(200);
      expect((yield* request("/api/deleteResource", { identifier: urn.identifier })).status).toBe(
        200,
      );
    }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live("managed clients accept several redirect URIs and can be edited", () =>
    Effect.gen(function* () {
      const created = yield* request("/api/createClient", {
        client_name: "Multi-callback client",
        redirect_uris: ["http://127.0.0.1:9876/callback", "http://localhost:5173/callback"],
        resources: [],
        application_type: "native",
        token_endpoint_auth_method: "client_secret_post",
      });

      expect(created.status, yield* text(created)).toBe(201);
      const app = yield* json(created);
      expect(app.redirect_uris).toEqual([
        "http://127.0.0.1:9876/callback",
        "http://localhost:5173/callback",
      ]);
      expect(app.token_endpoint_auth_method).toBe("client_secret_post");

      const updated = yield* request("/api/updateClient", {
        client_id: app.client_id,
        client_name: "Renamed client",
        redirect_uris: ["https://app.internal/callback"],
        application_type: "web",
      });

      expect(updated.status, yield* text(updated)).toBe(200);
      expect(yield* json(updated)).toMatchObject({
        client_id: app.client_id,
        client_name: "Renamed client",
        redirect_uris: ["https://app.internal/callback"],
        application_type: "web",
      });

      const stored = (yield* listing()).clients.find(
        (row: { client_id: string }) => row.client_id === app.client_id,
      );

      expect(stored).toMatchObject({
        client_name: "Renamed client",
        redirect_uris: ["https://app.internal/callback"],
        application_type: "web",
      });
      expect(
        (yield* request("/api/updateClient", {
          client_id: app.client_id,
          client_name: "Loopback web client",
          redirect_uris: ["http://127.0.0.1:9876/callback"],
          application_type: "web",
        })).status,
      ).toBe(400);
    }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live(
    "a client registered without resources can later authorize an HTTP resource with basic scope tokens",
    () =>
      Effect.gen(function* () {
        const created = yield* request("/api/createClient", {
          client_name: "Client before resources",
          redirect_uris: ["http://127.0.0.1:9876/callback"],
          resources: [],
          application_type: "native",
          token_endpoint_auth_method: "none",
        });

        expect(created.status, yield* text(created)).toBe(201);
        const app = yield* json(created);
        expect((yield* listing()).clientAccess).toEqual([]);
        expect((yield* listing()).resources).toEqual([administrationResource(baseURL)]);

        const resource = {
          identifier: "http://api.internal/mcp",
          name: "HTTP resource",
          scopes: ["r", "Files.Read", "read_all"],
        };

        const added = yield* request("/api/putResource", resource);
        expect(added.status, yield* text(added)).toBe(200);
        const flow = authorization(app.client_id, resource.identifier, { scope: "r" });
        const denied = yield* request(flow.path);
        expect(denied.status).not.toBe(200);
        expect(denied.headers.get("location") ?? "").not.toContain("/consent");
        expect((yield* access(app.client_id, [resource.identifier])).status).toBe(200);

        const issued = yield* tokens(
          app.client_id,
          resource.identifier,
          undefined,
          resource.scopes.join(" "),
        );

        const keys = createLocalJWKSet(yield* json(yield* request("/api/auth/jwks")));

        const { payload: claims } = yield* Effect.promise(() =>
          jwtVerify(issued.access_token, keys, {
            issuer: `${baseURL}/api/auth`,
            audience: resource.identifier,
            typ: "at+jwt",
          }),
        );

        expect(claims.aud).toBe(resource.identifier);
        expect(new Set(String(claims.scope).split(" "))).toEqual(new Set(resource.scopes));
      }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live("one client accesses multiple resources but each token request targets one", () =>
    Effect.gen(function* () {
      const app = yield* client();
      expect((yield* access(app.client_id, [resourceA, resourceB])).status).toBe(200);
      const rows = (yield* listing()).clientAccess;
      expect(rows).toEqual(
        expect.arrayContaining([
          { client_id: app.client_id, resource: resourceA },
          { client_id: app.client_id, resource: resourceB },
        ]),
      );
      expect((yield* tokens(app.client_id, resourceA)).access_token).toBeTypeOf("string");
      expect((yield* tokens(app.client_id, resourceB)).access_token).toBeTypeOf("string");
      expect(
        (yield* access(app.client_id, [resourceA, "https://missing.internal/api"])).status,
      ).toBe(400);
      expect((yield* listing()).clientAccess).toEqual(rows);
      expect((yield* access(app.client_id, [])).status).toBe(200);
      expect((yield* listing()).clientAccess).toEqual([]);
      expect((yield* request("/api/deleteResource", { identifier: resourceA })).status).toBe(200);
    }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live("filtered access preserves ordering and isolates clients sharing a resource", () =>
    Effect.gen(function* () {
      const first = yield* client();
      const second = yield* client();
      const linked = yield* access(first.client_id, [resourceB, resourceA]);
      expect(linked.status).toBe(200);
      expect((yield* json(linked)).clientAccess).toEqual([
        { client_id: first.client_id, resource: resourceA },
        { client_id: first.client_id, resource: resourceB },
      ]);
      expect(yield* (yield* ResourceCatalog).hasAccess(first.client_id, resourceB)).toBe(true);
      expect(yield* (yield* ResourceCatalog).hasAccess(second.client_id, resourceB)).toBe(false);
      expect(yield* (yield* ResourceCatalog).hasAccess("missing", resourceA)).toBe(false);
      expect((yield* access(first.client_id, [])).status).toBe(200);
      expect((yield* listing()).clientAccess).toEqual([
        { client_id: second.client_id, resource: resourceA },
      ]);
      expect((yield* request("/api/deleteResource", { identifier: resourceA })).status).toBe(200);
      expect((yield* listing()).clientAccess).toEqual([]);
      expect((yield* request("/api/deleteResource", { identifier: resourceB })).status).toBe(200);
    }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live("the same scope label has independent consent on each resource", () =>
    Effect.gen(function* () {
      const app = yield* dynamicClient;
      expect((yield* putResource(resourceB, ["notes:read", "notes:write"])).status).toBe(200);
      yield* authorize(app.client_id, resourceA);
      const responseB = yield* request(unprompted(app.client_id, resourceB).path);
      const consentB = new URL(responseB.headers.get("location")!, baseURL);
      expect(consentB.pathname).toBe("/consent");
      expect(
        (yield* request("/api/auth/oauth2/consent", {
          accept: true,
          oauth_query: consentB.search.slice(1),
        })).status,
      ).toBe(200);

      const consents =
        yield* sql`SELECT referenceId, resources FROM oauthConsent WHERE clientId = ${app.client_id} ORDER BY referenceId`;

      expect(consents).toEqual(
        [
          { referenceId: `resource:${resourceA}`, resources: JSON.stringify([resourceA]) },
          { referenceId: `resource:${resourceB}`, resources: JSON.stringify([resourceB]) },
        ].sort((a, b) => a.referenceId.localeCompare(b.referenceId)),
      );

      for (const resource of [resourceA, resourceB]) {
        const prior = yield* request(
          authorization(app.client_id, resource, { prompt: "none" }).path,
        );

        const redirect = new URL(prior.headers.get("location")!, baseURL);
        expect(redirect.searchParams.has("code")).toBe(true);
        expect(redirect.searchParams.has("error")).toBe(false);
      }
    }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live(
    "new scopes appear immediately and need consent; name-only changes preserve refresh grants",
    () =>
      Effect.gen(function* () {
        const app = yield* dynamicClient;
        const issued = yield* tokens(app.client_id);
        expect(
          (yield* putResource(resourceA, ["notes:read", "notes:write"], "Renamed")).status,
        ).toBe(200);
        expect((yield* refresh(app.client_id, issued.refresh_token, resourceA)).status).toBe(200);
        expect(
          (yield* putResource(resourceA, ["notes:read", "notes:write", "notes:admin"])).status,
        ).toBe(200);

        const metadata = yield* json(
          yield* request("/.well-known/oauth-authorization-server/api/auth"),
        );

        expect(metadata.scopes_supported).toContain("notes:admin");

        const stored = (yield* listing()).clients.find(
          (row: { client_id: string }) => row.client_id === app.client_id,
        );

        expect(stored.scope.split(" ")).toContain("notes:admin");

        const response = yield* request(
          authorization(app.client_id, resourceA, { scope: "notes:admin", prompt: "none" }).path,
        );

        expect(new URL(response.headers.get("location")!, baseURL).searchParams.get("error")).toBe(
          "consent_required",
        );
      }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live(
    "scope removal narrows issued scopes while unconsumed grants retain their original consent",
    () =>
      Effect.gen(function* () {
        const app = yield* client();
        expect((yield* access(app.client_id, [resourceA, resourceB])).status).toBe(200);
        expect((yield* putResource(resourceB, ["notes:read", "notes:write"])).status).toBe(200);
        const sharedScopes = "offline_access notes:read";
        const issuedA = yield* tokens(app.client_id, resourceA);
        const retainedRefreshA = yield* tokens(app.client_id, resourceA);
        const issuedB = yield* tokens(app.client_id, resourceB, undefined, sharedScopes);
        const pendingA = yield* authorize(app.client_id, resourceA);
        const retainedA = yield* authorize(app.client_id, resourceA);
        const pendingB = yield* authorize(app.client_id, resourceB, sharedScopes);
        expect((yield* putResource(resourceA, ["notes:write"])).status).toBe(200);
        const narrowed = yield* refresh(app.client_id, issuedA.refresh_token, resourceA);
        expect(narrowed.status).toBe(200);
        const narrowedToken = yield* json(narrowed);
        expect(narrowedToken.scope.split(" ")).not.toContain("notes:read");
        const keys = createLocalJWKSet(yield* json(yield* request("/api/auth/jwks")));

        const verified = yield* Effect.promise(() =>
          jwtVerify(narrowedToken.access_token, keys, { audience: resourceA }),
        );

        expect(String(verified.payload.scope).split(" ")).not.toContain("notes:read");
        const narrowedCode = yield* exchange(app.client_id, pendingA, resourceA);
        expect(narrowedCode.status).toBe(200);
        expect((yield* json(narrowedCode)).scope.split(" ")).not.toContain("notes:read");
        expect((yield* refresh(app.client_id, issuedB.refresh_token, resourceB)).status).toBe(200);
        expect((yield* exchange(app.client_id, pendingB, resourceB)).status).toBe(200);
        expect((yield* putResource(resourceA, ["notes:read", "notes:write"])).status).toBe(200);

        const restoredRefresh = yield* refresh(
          app.client_id,
          retainedRefreshA.refresh_token,
          resourceA,
        );

        expect(restoredRefresh.status).toBe(200);
        expect((yield* json(restoredRefresh)).scope.split(" ")).toContain("notes:read");
        const restoredCode = yield* exchange(app.client_id, retainedA, resourceA);
        expect(restoredCode.status).toBe(200);
        expect((yield* json(restoredCode)).scope.split(" ")).toContain("notes:read");
        expect((yield* exchange(app.client_id, pendingA, resourceA)).status).toBe(400);
      }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live("removing access revokes that resource's authorization and leaves the others", () =>
    Effect.gen(function* () {
      const app = yield* client();
      expect((yield* access(app.client_id, [resourceA, resourceB])).status).toBe(200);
      const issuedA = yield* tokens(app.client_id, resourceA);
      const issuedB = yield* tokens(app.client_id, resourceB);
      const pendingA = yield* authorize(app.client_id, resourceA);

      const consents = () =>
        sql`SELECT referenceId FROM oauthConsent WHERE clientId = ${app.client_id} ORDER BY referenceId`;

      const consentsBefore = yield* consents();
      expect(consentsBefore).toContainEqual({ referenceId: `resource:${resourceA}` });
      expect((yield* access(app.client_id, [resourceB])).status).toBe(200);
      expect(yield* consents()).toEqual(
        consentsBefore.filter((row) => row.referenceId !== `resource:${resourceA}`),
      );
      expect((yield* refresh(app.client_id, issuedA.refresh_token, resourceA)).status).toBe(400);

      expect((yield* access(app.client_id, [resourceA, resourceB])).status).toBe(200);
      expect((yield* refresh(app.client_id, issuedA.refresh_token, resourceA)).status).toBe(400);
      expect((yield* exchange(app.client_id, pendingA, resourceA)).status).toBe(400);
      expect((yield* refresh(app.client_id, issuedB.refresh_token, resourceB)).status).toBe(200);

      const unaffected = yield* request(
        authorization(app.client_id, resourceB, {
          scope: "offline_access reports:read",
          prompt: "none",
        }).path,
      );

      expect(new URL(unaffected.headers.get("location")!, baseURL).searchParams.has("code")).toBe(
        true,
      );
    }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live("a failed provider resource write preserves stored policy and live discovery", () =>
    Effect.gen(function* () {
      const app = yield* client();
      const before = yield* listing();

      const metadataBefore = yield* json(
        yield* request("/.well-known/oauth-authorization-server/api/auth"),
      );

      yield* Effect.acquireUseRelease(
        sql`CREATE TRIGGER reject_scope_update BEFORE UPDATE OF allowedScopes ON oauthResource BEGIN SELECT RAISE(ABORT, 'injected scope failure'); END`,
        () =>
          Effect.gen(function* () {
            expect((yield* putResource(resourceA, ["notes:read", "new:scope"])).status).toBe(500);
            expect(yield* listing()).toEqual(before);

            const metadataAfter = yield* json(
              yield* request("/.well-known/oauth-authorization-server/api/auth"),
            );

            expect(metadataAfter.scopes_supported).toEqual(metadataBefore.scopes_supported);
          }),
        () => sql`DROP TRIGGER reject_scope_update`,
      );

      expect((yield* tokens(app.client_id)).access_token).toBeTypeOf("string");
    }).pipe(Effect.provide(signedInIssuer())),
  );

  it.live("overlapping link and delete requests leave consistent resource access", () =>
    Effect.gen(function* () {
      const app = yield* client();

      const results = yield* Effect.all(
        [
          access(app.client_id, [resourceA, resourceB]),
          request("/api/deleteResource", { identifier: resourceB }),
        ],
        { concurrency: "unbounded" },
      );

      // why: linking races the deletion, so it may lose at any provider step
      expect([200, 400, 404]).toContain(results[0]?.status);
      expect(results[1]?.status).toBe(200);
      const state = yield* listing();

      for (const link of state.clientAccess) {
        expect(
          state.resources.some(
            (resource: { identifier: string }) => resource.identifier === link.resource,
          ),
        ).toBe(true);
      }
    }).pipe(Effect.provide(signedInIssuer())),
  );
});
