import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Redacted, Effect, Schema } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { HttpApiClient } from "effect/unstable/httpapi";
import { Api, BadRequest } from "@clankerauth/api";
import { webApplication as application } from "./web-application.ts";
import { initialize, openAuth, type Service } from "../src/auth.ts";
import { validateSettings, type Settings } from "../src/config.ts";

import { administrationResource } from "./mcp-oauth-helper.ts";

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
      secret: Redacted.make(randomBytes(32).toString("hex")),
      database: join(directory, "auth.sqlite"),
      host: "127.0.0.1",
      port: 3000,
    });
    service = await Effect.runPromise(openAuth(settings));
    await Effect.runPromise(initialize(service));
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

  test("generated client shares setup, owner authorization and client lifecycle", async () => {
    await Effect.gen(function* () {
      const api = yield* HttpApiClient.make(Api, { baseUrl: settings.baseURL });
      expect(yield* api.issuer.setupStatus({ payload: {} })).toEqual({ required: true });
      expect(yield* api.issuer.setupOwner({ payload: { email, password } })).toEqual({
        created: true,
      });
      expect(yield* api.issuer.setupStatus({ payload: {} })).toEqual({ required: false });

      const repeatedSetup = yield* Effect.flip(
        api.issuer.setupOwner({ payload: { email, password } }),
      );

      expect(repeatedSetup._tag).toBe("Conflict");

      const anonymous = yield* Effect.flip(api.administration.listClients({ payload: {} }));
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

      const resourceInput = {
        identifier: resource,
        name: "Example MCP",
        scopes: ["example:read"],
      };

      expect((yield* api.administration.listClients({ payload: {} })).resources).toEqual([
        administrationResource(settings.baseURL),
      ]);
      yield* api.administration.createResource({ payload: resourceInput });

      const created = yield* api.administration.createClient({
        payload: {
          name: "Contract test client",
          redirect: "http://127.0.0.1:9876/callback",
          resources: [resource],
          native: true,
          confidential: true,
        },
      });

      expect(created.client_secret).toBeTypeOf("string");

      const publicClient = yield* api.administration.createClient({
        payload: {
          name: "Public contract client",
          redirect: "http://127.0.0.1:9876/callback",
          resources: [],
          native: true,
          confidential: false,
        },
      });

      expect(publicClient.client_secret).toBeUndefined();
      yield* api.administration.deleteClient({ payload: { client_id: publicClient.client_id } });
      const listing = yield* api.administration.listClients({ payload: {} });
      expect(listing.email).toBe(email);
      expect(listing.issuer).toBe(`${settings.baseURL}/api/auth`);
      expect(listing.resources).toEqual([
        administrationResource(settings.baseURL),
        { ...resourceInput, builtIn: false },
      ]);
      expect(listing.clientAccess).toEqual([{ client_id: created.client_id, resource }]);
      expect(listing.clients.map((client) => client.client_id)).toEqual([created.client_id]);
      expect(listing.clients[0]).not.toHaveProperty("client_secret");

      const updatedResource = {
        ...resourceInput,
        name: "Renamed MCP",
        scopes: ["example:read", "example:write"],
      };

      expect(yield* api.administration.updateResource({ payload: updatedResource })).toEqual(
        updatedResource,
      );
      expect(
        yield* api.administration.setClientAccess({
          payload: { client_id: created.client_id, resources: [] },
        }),
      ).toEqual({ clientAccess: [] });
      expect(
        yield* api.administration.setClientAccess({
          payload: { client_id: created.client_id, resources: [resource] },
        }),
      ).toEqual({ clientAccess: [{ client_id: created.client_id, resource }] });

      const rotated = yield* api.administration.rotateClientSecret({
        payload: { client_id: created.client_id },
      });

      expect(rotated.client_secret).toBeTypeOf("string");
      expect(rotated.client_secret).not.toBe(created.client_secret);

      expect(
        yield* api.administration.revokeClient({ payload: { client_id: created.client_id } }),
      ).toEqual({
        revoked: true,
      });
      expect(
        yield* api.administration.blockClient({
          payload: { client_id: created.client_id, blocked: true },
        }),
      ).toEqual({ blocked: true });
      expect((yield* api.administration.listClients({ payload: {} })).clients[0]?.blocked).toBe(
        true,
      );
      // Blocking issuance must not block the owner's provider-backed resource maintenance.
      expect(yield* api.administration.updateResource({ payload: updatedResource })).toEqual(
        updatedResource,
      );
      expect(
        yield* api.administration.blockClient({
          payload: { client_id: created.client_id, blocked: false },
        }),
      ).toEqual({ blocked: false });
      expect((yield* api.administration.listClients({ payload: {} })).clients[0]?.blocked).toBe(
        false,
      );
      // Persisted values must satisfy the outgoing contract; corrupt data is a
      // server failure, not a bad request from this correctly typed caller.
      yield* service.sql`UPDATE oauthClient SET redirectUris = ${JSON.stringify([42])} WHERE clientId = ${created.client_id}`;
      const invalidResponse = yield* Effect.flip(api.administration.listClients({ payload: {} }));
      expect(invalidResponse._tag).toBe("InternalServerError");
      expect(
        yield* api.administration.deleteClient({ payload: { client_id: created.client_id } }),
      ).toEqual({
        deleted: true,
      });
      expect((yield* api.administration.listClients({ payload: {} })).clients).toEqual([]);
      expect(
        yield* api.administration.deleteResource({ payload: { identifier: resource } }),
      ).toEqual({
        deleted: true,
      });
      expect((yield* api.administration.listClients({ payload: {} })).resources).toEqual([
        administrationResource(settings.baseURL),
      ]);
    }).pipe(
      Effect.provide(FetchHttpClient.layer),
      Effect.provideService(FetchHttpClient.Fetch, appFetch),
      Effect.runPromise,
    );
  });

  test("automatic clients are visible and manageable through the generated owner API", async () => {
    await Effect.gen(function* () {
      const api = yield* HttpApiClient.make(Api, { baseUrl: settings.baseURL });
      yield* api.issuer.setupOwner({ payload: { email, password } });

      const login = yield* Effect.promise(() =>
        appFetch(`${settings.baseURL}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, password }),
        }),
      );

      cookie = login.headers
        .getSetCookie()
        .map((value) => value.split(";")[0])
        .join("; ");
      yield* api.administration.createResource({
        payload: { identifier: resource, name: "MCP", scopes: ["example:read"] },
      });

      const registration = yield* Effect.promise(() =>
        handle(
          new Request(`${settings.baseURL}/api/auth/oauth2/register`, {
            method: "POST",
            headers: { "content-type": "application/json", "x-clankerauth-peer": "127.0.0.1" },
            body: JSON.stringify({
              client_name: "Automatic MCP",
              redirect_uris: ["http://127.0.0.1:9876/callback"],
              token_endpoint_auth_method: "none",
              grant_types: ["authorization_code", "refresh_token"],
            }),
          }),
        ),
      );

      expect(registration.status).toBe(201);
      expect(registration.headers.get("access-control-allow-origin")).toBe("*");
      expect(registration.headers.has("access-control-allow-credentials")).toBe(false);

      const preflight = yield* Effect.promise(() =>
        handle(
          new Request(`${settings.baseURL}/api/auth/oauth2/register`, {
            method: "OPTIONS",
            headers: {
              origin: "https://mcp-client.example",
              "access-control-request-method": "POST",
              "access-control-request-headers": "content-type",
            },
          }),
        ),
      );

      expect(preflight.status).toBe(204);
      expect(preflight.headers.get("access-control-allow-methods")).toContain("POST");
      const registered = yield* Effect.promise(() => registration.json());
      const client_id = yield* Schema.decodeUnknownEffect(Schema.String)(registered.client_id);
      const listing = yield* api.administration.listClients({ payload: {} });
      expect(listing.clients).toHaveLength(1);
      expect(listing.clients[0]).toMatchObject({ client_id, onboarding: "dcr", blocked: false });
      expect(listing.clients[0]).not.toHaveProperty("client_secret");
      expect(listing.clientAccess).toEqual([
        { client_id, resource: `${settings.baseURL}/mcp` },
        { client_id, resource },
      ]);
      expect(
        (yield* Effect.flip(
          api.administration.setClientAccess({ payload: { client_id, resources: [] } }),
        ))._tag,
      ).toBe("BadRequest");
      expect(yield* api.administration.revokeClient({ payload: { client_id } })).toEqual({
        revoked: true,
      });
      expect(
        yield* api.administration.blockClient({ payload: { client_id, blocked: true } }),
      ).toEqual({
        blocked: true,
      });
      expect((yield* api.administration.listClients({ payload: {} })).clients[0]?.blocked).toBe(
        true,
      );
      expect(
        yield* api.administration.blockClient({ payload: { client_id, blocked: false } }),
      ).toEqual({
        blocked: false,
      });
      expect((yield* api.administration.listClients({ payload: {} })).clients[0]?.blocked).toBe(
        false,
      );
      expect(
        yield* api.administration.deleteResource({ payload: { identifier: resource } }),
      ).toEqual({
        deleted: true,
      });
      expect((yield* api.administration.listClients({ payload: {} })).clientAccess).toEqual([
        { client_id, resource: `${settings.baseURL}/mcp` },
      ]);

      // Retained policy and nullable live metadata are distinct cases. An owned
      // automatic client must also appear only once in the combined listing.
      const retainedId = "https://retained.example/client.json";
      yield* service.sql`INSERT INTO clientOnboarding (clientId, source, blocked) VALUES (${retainedId}, 'cimd', 1)`;
      yield* service.sql`UPDATE clientOnboarding SET source = 'cimd' WHERE clientId = ${client_id}`;
      yield* service.sql`UPDATE oauthClient SET userId = ${yield* service.owner()}, name = NULL, tokenEndpointAuthMethod = NULL, scopes = NULL, grantTypes = NULL WHERE clientId = ${client_id}`;
      const combined = (yield* api.administration.listClients({ payload: {} })).clients;
      expect(combined).toHaveLength(2);
      expect(combined.find((client) => client.client_id === retainedId)).toEqual({
        client_id: retainedId,
        onboarding: "cimd",
        blocked: true,
        redirect_uris: [],
      });
      expect(combined.find((client) => client.client_id === client_id)).toEqual({
        client_id,
        onboarding: "cimd",
        blocked: false,
        redirect_uris: ["http://127.0.0.1:9876/callback"],
      });

      for (const invalidRedirects of ["null", "[42]"]) {
        yield* service.sql`UPDATE oauthClient SET redirectUris = ${invalidRedirects} WHERE clientId = ${client_id}`;
        expect((yield* Effect.flip(api.administration.listClients({ payload: {} })))._tag).toBe(
          "InternalServerError",
        );
      }

      cookie = "";
      expect(
        (yield* Effect.flip(
          api.administration.blockClient({ payload: { client_id, blocked: true } }),
        ))._tag,
      ).toBe("Unauthorized");
      expect(
        (yield* Effect.flip(api.administration.revokeClient({ payload: { client_id } })))._tag,
      ).toBe("Unauthorized");
    }).pipe(
      Effect.provide(FetchHttpClient.layer),
      Effect.provideService(FetchHttpClient.Fetch, appFetch),
      Effect.runPromise,
    );
  });

  test("client administration returns 404 for missing clients and 500 for failed writes", async () => {
    await Effect.gen(function* () {
      const api = yield* HttpApiClient.make(Api, { baseUrl: settings.baseURL });
      yield* api.issuer.setupOwner({ payload: { email, password } });

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
      const missing = { client_id: "missing-client" };
      expect((yield* Effect.flip(api.administration.revokeClient({ payload: missing })))._tag).toBe(
        "NotFound",
      );

      for (const blocked of [true, false]) {
        expect(
          (yield* Effect.flip(api.administration.blockClient({ payload: { ...missing, blocked } })))
            ._tag,
        ).toBe("NotFound");
      }

      const client = yield* api.administration.createClient({
        payload: {
          name: "Failure test",
          redirect: "http://127.0.0.1:9876/callback",
          resources: [],
          native: true,
          confidential: false,
        },
      });

      const client_id = client.client_id;
      yield* service.sql`INSERT INTO oauthConsent (id, clientId, userId, scopes, createdAt, updatedAt) VALUES ('failure-consent', ${client_id}, ${yield* service.owner()}, '[]', ${Date.now()}, ${Date.now()})`;
      yield* service.sql`CREATE TRIGGER fail_revoke BEFORE DELETE ON oauthConsent BEGIN SELECT RAISE(ABORT, 'injected database failure'); END`;
      expect(
        (yield* Effect.flip(api.administration.revokeClient({ payload: { client_id } })))._tag,
      ).toBe("InternalServerError");
      expect(
        (yield* Effect.flip(
          api.administration.blockClient({ payload: { client_id, blocked: true } }),
        ))._tag,
      ).toBe("InternalServerError");
      // Failed revocation also rolls back the disabled flag written by block.
      expect((yield* api.administration.listClients({ payload: {} })).clients[0]?.blocked).toBe(
        false,
      );
      expect(yield* service.sql`SELECT id FROM oauthConsent WHERE clientId = ${client_id}`).toEqual(
        [{ id: "failure-consent" }],
      );
    }).pipe(
      Effect.provide(FetchHttpClient.layer),
      Effect.provideService(FetchHttpClient.Fetch, appFetch),
      Effect.runPromise,
    );
  });

  test("malformed setup payload returns 400 without reflecting sensitive input", async () => {
    const response = await appFetch(`${settings.baseURL}/api/issuer/setupOwner`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: { sensitive: password } }),
    });

    expect(response.status).toBe(400);
    const body = await response.text();
    expect(body).not.toContain(password);
    expect(JSON.parse(body)).toEqual(
      Schema.encodeSync(BadRequest)(new BadRequest({ error: "Invalid request" })),
    );
    expect(await Effect.runPromise(service.owner())).toBeUndefined();
  });
});
