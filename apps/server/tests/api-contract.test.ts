import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Schema } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { HttpApiClient } from "effect/unstable/httpapi";
import { Api } from "@clankerauth/api";
import { application } from "../src/app.ts";
import { initialize, openAuth, type Service } from "../src/auth.ts";
import { validateSettings, type Settings } from "../src/config.ts";

describe("API integration", () => {
  const email = "owner@example.internal";
  const password = "test-only owner password 8rS!";
  const resource = "https://example.internal/mcp";
  let directory: string;
  let service: Service;
  let handle: ReturnType<typeof application>;
  let settings: Settings;
  let cookie: string;

  beforeEach(async () => {
    directory = mkdtempSync(join(tmpdir(), "clankerauth-contract-"));
    settings = validateSettings({
      baseURL: "http://localhost:3000",
      secret: randomBytes(32).toString("hex"),
      database: join(directory, "auth.sqlite"),
      host: "127.0.0.1",
      port: 3000,
      resources: [{ identifier: resource, name: "Example MCP", scopes: ["example:read"] }],
    });
    service = openAuth(settings);
    await initialize(service);
    handle = application(service);
    cookie = "";
  });

  afterEach(async () => {
    await handle.dispose();
    await service.close();
    rmSync(directory, { recursive: true, force: true });
  });

  // Model the browser's same-origin headers and cookie transport while exercising
  // the actual FetchHttpClient request encoding and HttpApiClient response decoding.
  const appFetch: typeof fetch = (input, init) => {
    const request = new Request(input, init);
    request.headers.set("origin", settings.baseURL);
    request.headers.set("cookie", cookie);
    request.headers.set("x-clankerauth-peer", "127.0.0.1");
    return handle(request);
  };

  test.each([true, false])(
    "generated client shares setup, owner authorization and client lifecycle (confidential=%s)",
    async (confidential) => {
      await Effect.gen(function* () {
        const api = yield* HttpApiClient.make(Api, { baseUrl: settings.baseURL });
        expect(yield* api.setup.status()).toEqual({ required: true });
        expect(yield* api.setup.create({ payload: { email, password } })).toEqual({
          created: true,
        });
        expect(yield* api.setup.status()).toEqual({ required: false });
        const repeatedSetup = yield* Effect.flip(
          api.setup.create({ payload: { email, password } }),
        );
        expect(repeatedSetup._tag).toBe("Conflict");

        const anonymous = yield* Effect.flip(api.clients.list());
        expect(anonymous._tag).toBe("Unauthorized");

        const login = yield* Effect.promise(() =>
          appFetch(`${settings.baseURL}/api/auth/sign-in/email`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ email, password }),
          }),
        );
        expect(login.status).toBe(200);
        cookie = login.headers
          .getSetCookie()
          .map((value) => value.split(";")[0])
          .join("; ");
        expect(cookie).not.toBe("");

        const created = yield* api.clients.create({
          payload: {
            name: "Contract test client",
            redirect: "http://127.0.0.1:9876/callback",
            resource,
            native: true,
            confidential,
          },
        });
        if (confidential) expect(created.client_secret).toBeTypeOf("string");
        else expect(created.client_secret).toBeUndefined();
        const listing = yield* api.clients.list();
        expect(listing.email).toBe(email);
        expect(listing.issuer).toBe(`${settings.baseURL}/api/auth`);
        expect(listing.resources).toEqual(settings.resources);
        expect(listing.clients.map((client) => client.client_id)).toEqual([created.client_id]);
        expect(listing.clients[0]).not.toHaveProperty("client_secret");

        if (confidential) {
          const rotated = yield* api.clients.rotate({ payload: { client_id: created.client_id } });
          expect(rotated.client_secret).toBeTypeOf("string");
          expect(rotated.client_secret).not.toBe(created.client_secret);
        }
        // Persisted values must satisfy the outgoing contract; corrupt data is a
        // server failure, not a bad request from this correctly typed caller.
        service.db
          .prepare("UPDATE oauthClient SET redirectUris = ? WHERE clientId = ?")
          .run(JSON.stringify([42]), created.client_id);
        const invalidResponse = yield* Effect.flip(api.clients.list());
        expect(invalidResponse._tag).toBe("InternalServerError");
        expect(yield* api.clients.delete({ payload: { client_id: created.client_id } })).toEqual({
          deleted: true,
        });
        expect((yield* api.clients.list()).clients).toEqual([]);
      }).pipe(
        Effect.provide(FetchHttpClient.layer),
        Effect.provideService(FetchHttpClient.Fetch, appFetch),
        Effect.runPromise,
      );
    },
  );

  test("malformed setup payload returns 400 without reflecting sensitive input", async () => {
    const response = await appFetch(`${settings.baseURL}/api/setup`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: { sensitive: password } }),
    });
    expect(response.status).toBe(400);
    const body = await response.text();
    expect(body).not.toContain(password);
    expect(JSON.parse(body)).toMatchObject({ _tag: "BadRequest" });
    expect(service.owner()).toBeUndefined();
  });
});

test("generated client rejects a successful response that violates the shared schema", async () => {
  const error = await Effect.gen(function* () {
    const api = yield* HttpApiClient.make(Api, { baseUrl: "http://localhost:3000" });
    return yield* Effect.flip(api.setup.status());
  }).pipe(
    Effect.provide(FetchHttpClient.layer),
    Effect.provideService(FetchHttpClient.Fetch, async () => Response.json({ required: "yes" })),
    Effect.runPromise,
  );
  expect(Schema.isSchemaError(error)).toBe(true);
});
