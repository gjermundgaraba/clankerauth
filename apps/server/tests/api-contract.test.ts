import { it } from "@effect/vitest";
import { describe, expect, vi } from "vite-plus/test";
import { Context, Effect, Layer, Schema } from "effect";
import { FetchHttpClient } from "effect/http";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { Http, ServiceUnavailable } from "@clankerauth/admin-api";
import { APIError } from "better-auth/api";
import { testWebApplication, WebApplication } from "./test-issuer.ts";

import { administrationResource } from "./mcp-oauth-helper.ts";
import { Database } from "../src/platform/sqlite.ts";
import { OwnerAccount } from "../src/owner/owner.ts";
import { Issuer } from "../src/issuer/issuer.ts";

/** A typed client of the issuer's binding, as an HTTP caller of the issuer builds one. */
const apiClient = (baseUrl: string) => ActionHttp.client(Http, { baseUrl });

const baseURL = "http://localhost:3000";

/** The issuer's web application, as a browser on its origin reaches it. */
class Browser extends Context.Service<
  Browser,
  {
    readonly handle: (request: Request) => Promise<Response>;
    readonly fetch: typeof fetch;
    cookie: string;
  }
>()("api-contract.test/Browser") {}

// Model the browser's same-origin headers and cookie transport while exercising
// the actual FetchHttpClient request encoding and HttpApiClient response decoding.
const browser = Layer.effect(
  Browser,
  Effect.gen(function* () {
    const handle = yield* WebApplication;

    const self: Browser["Service"] = {
      handle,
      fetch: (input, init) => {
        const request = new Request(input, init);
        request.headers.set("origin", baseURL);
        request.headers.set("cookie", self.cookie);
        request.headers.set("x-clankerauth-peer", "127.0.0.1");

        return handle(request);
      },
      cookie: "",
    };

    return self;
  }),
);

const contractIssuer = () =>
  Layer.mergeAll(
    FetchHttpClient.layer,
    Layer.effect(
      FetchHttpClient.Fetch,
      Effect.map(Browser, ({ fetch }) => fetch),
    ),
  ).pipe(Layer.provideMerge(browser), Layer.provideMerge(testWebApplication({ baseURL })));

describe("API integration", () => {
  const email = "owner@example.internal";
  const password = "test-only owner password 8rS!";
  const resource = "https://example.internal/mcp";

  it.live("generated client shares setup, owner authorization and client lifecycle", () =>
    Effect.gen(function* () {
      const browser = yield* Browser;
      const { sql } = yield* Database;
      const api = yield* apiClient(baseURL);
      expect(yield* api.setupStatus()).toEqual({ required: true });
      expect(yield* api.setupOwner({ email, password })).toEqual({
        created: true,
      });
      expect(yield* api.setupStatus()).toEqual({ required: false });

      const repeatedSetup = yield* Effect.flip(api.setupOwner({ email, password }));

      expect(repeatedSetup._tag).toBe("OwnerExists");

      const anonymous = yield* Effect.flip(api.listClients());
      expect(anonymous._tag).toBe("Unauthenticated");

      const login = yield* Effect.promise(() =>
        browser.fetch(`${baseURL}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, password }),
        }),
      );

      expect(login.status).toBe(200);
      browser.cookie = login.headers
        .getSetCookie()
        .map((value) => value.split(";")[0])
        .join("; ");
      expect(browser.cookie).not.toBe("");

      const resourceInput = {
        identifier: resource,
        name: "Example MCP",
        scopes: ["example:read"],
      };

      expect((yield* api.listClients()).resources).toEqual([administrationResource(baseURL)]);
      yield* api.createResource(resourceInput);

      const created = yield* api.createClient({
        client_name: "Contract test client",
        redirect_uris: ["http://127.0.0.1:9876/callback"],
        resources: [resource],
        application_type: "native",
        token_endpoint_auth_method: "client_secret_basic",
      });

      expect(created.client_secret).toBeTypeOf("string");

      const publicClient = yield* api.createClient({
        client_name: "Public contract client",
        redirect_uris: ["http://127.0.0.1:9876/callback"],
        resources: [],
        application_type: "native",
        token_endpoint_auth_method: "none",
      });

      expect(publicClient.client_secret).toBeUndefined();
      yield* api.deleteClient({ client_id: publicClient.client_id });
      const listing = yield* api.listClients();
      expect(listing.email).toBe(email);
      expect(listing.issuer).toBe(`${baseURL}/api/auth`);
      expect(listing.resources).toEqual([
        administrationResource(baseURL),
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

      expect(yield* api.updateResource(updatedResource)).toEqual(updatedResource);
      expect(yield* api.setClientAccess({ client_id: created.client_id, resources: [] })).toEqual({
        clientAccess: [],
      });
      expect(
        yield* api.setClientAccess({
          client_id: created.client_id,
          resources: [resource],
        }),
      ).toEqual({ clientAccess: [{ client_id: created.client_id, resource }] });

      const rotated = yield* api.rotateClientSecret({
        client_id: created.client_id,
      });

      expect(rotated.client_secret).toBeTypeOf("string");
      expect(rotated.client_secret).not.toBe(created.client_secret);

      expect(yield* api.revokeClient({ client_id: created.client_id })).toEqual({
        revoked: true,
      });
      expect(yield* api.blockClient({ client_id: created.client_id, blocked: true })).toEqual({
        blocked: true,
      });
      expect((yield* api.listClients()).clients[0]?.blocked).toBe(true);
      // Blocking issuance must not block the owner's provider-backed resource maintenance.
      expect(yield* api.updateResource(updatedResource)).toEqual(updatedResource);
      expect(yield* api.blockClient({ client_id: created.client_id, blocked: false })).toEqual({
        blocked: false,
      });
      expect((yield* api.listClients()).clients[0]?.blocked).toBe(false);
      // Persisted values must satisfy the outgoing contract; corrupt data is a
      // server failure, not a bad request from this correctly typed caller.
      yield* sql`UPDATE oauthClient SET redirectUris = ${JSON.stringify([42])} WHERE clientId = ${created.client_id}`;
      const invalidResponse = yield* Effect.flip(api.listClients());
      expect(invalidResponse._tag).toBe("InternalServerError");
      expect(yield* api.deleteClient({ client_id: created.client_id })).toEqual({
        deleted: true,
      });
      expect((yield* api.listClients()).clients).toEqual([]);
      expect(yield* api.deleteResource({ identifier: resource })).toEqual({
        deleted: true,
      });
      expect((yield* api.listClients()).resources).toEqual([administrationResource(baseURL)]);
    }).pipe(Effect.provide(contractIssuer())),
  );

  it.live(
    "a session the provider cannot read answers the declared 503, which the client decodes",
    () =>
      Effect.gen(function* () {
        const browser = yield* Browser;
        const { auth, context } = yield* Issuer;
        // The owner session's verifier fails with an error `OwnerSession` declares, not a refusal:
        // signing in again cannot help.
        vi.spyOn(auth.api, "getSession").mockRejectedValue(
          new APIError("SERVICE_UNAVAILABLE", { message: "Session store unavailable" }),
        );
        browser.cookie = `${context.authCookies.sessionToken.name}=unreadable`;

        const response = yield* Effect.promise(() =>
          browser.fetch(`${baseURL}/api/listClients`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: "{}",
          }),
        );

        expect(response.status).toBe(503);
        expect(yield* Effect.promise(() => response.json())).toEqual(
          Schema.encodeSync(ServiceUnavailable)(
            new ServiceUnavailable({ message: "Session store unavailable" }),
          ),
        );

        const failure = yield* Effect.flip(
          Effect.flatMap(apiClient(baseURL), (api) => api.listClients()),
        );

        expect(failure).toBeInstanceOf(ServiceUnavailable);
      }).pipe(Effect.provide(contractIssuer())),
  );

  it.live("automatic clients are visible and manageable through the generated owner API", () =>
    Effect.gen(function* () {
      const browser = yield* Browser;
      const { sql } = yield* Database;
      const api = yield* apiClient(baseURL);
      yield* api.setupOwner({ email, password });

      const login = yield* Effect.promise(() =>
        browser.fetch(`${baseURL}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, password }),
        }),
      );

      browser.cookie = login.headers
        .getSetCookie()
        .map((value) => value.split(";")[0])
        .join("; ");
      yield* api.createResource({
        identifier: resource,
        name: "MCP",
        scopes: ["example:read"],
      });

      const registration = yield* Effect.promise(() =>
        browser.handle(
          new Request(`${baseURL}/api/auth/oauth2/register`, {
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
        browser.handle(
          new Request(`${baseURL}/api/auth/oauth2/register`, {
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
      const listing = yield* api.listClients();
      expect(listing.clients).toHaveLength(1);
      expect(listing.clients[0]).toMatchObject({ client_id, onboarding: "dcr", blocked: false });
      expect(listing.clients[0]).not.toHaveProperty("client_secret");
      // An automatic client may ask for any resource; consent decides, not client access.
      expect(listing.clientAccess).toEqual([]);
      expect(listing.connections).toEqual([]);
      expect((yield* Effect.flip(api.setClientAccess({ client_id, resources: [] })))._tag).toBe(
        "ClientIsAutomatic",
      );
      // The owner edits only the clients the owner registered.
      expect(
        (yield* Effect.flip(
          api.updateClient({
            client_id,
            client_name: "Renamed",
            redirect_uris: ["http://127.0.0.1:9876/callback"],
            application_type: "native",
          }),
        ))._tag,
      ).toBe("ClientIsAutomatic");
      expect(yield* api.revokeClient({ client_id })).toEqual({
        revoked: true,
      });
      expect(yield* api.blockClient({ client_id, blocked: true })).toEqual({
        blocked: true,
      });
      expect((yield* api.listClients()).clients[0]?.blocked).toBe(true);
      expect(yield* api.blockClient({ client_id, blocked: false })).toEqual({
        blocked: false,
      });
      expect((yield* api.listClients()).clients[0]?.blocked).toBe(false);
      expect(yield* api.deleteResource({ identifier: resource })).toEqual({
        deleted: true,
      });
      expect((yield* api.listClients()).resources.map((entry) => entry.identifier)).toEqual([
        `${baseURL}/`,
      ]);

      // Onboarding is derived from provider columns: metadata discovery marks CIMD clients
      // and nullable live metadata is omitted rather than invented.
      yield* sql`UPDATE oauthClient SET clientDiscoveryId = 'cimd', name = NULL, tokenEndpointAuthMethod = NULL, applicationType = NULL, scopes = NULL, grantTypes = NULL WHERE clientId = ${client_id}`;
      expect((yield* api.listClients()).clients).toEqual([
        {
          client_id,
          onboarding: "cimd",
          blocked: false,
          redirect_uris: ["http://127.0.0.1:9876/callback"],
          application_type: null,
        },
      ]);

      for (const invalidRedirects of ["null", "[42]"]) {
        yield* sql`UPDATE oauthClient SET redirectUris = ${invalidRedirects} WHERE clientId = ${client_id}`;
        expect((yield* Effect.flip(api.listClients()))._tag).toBe("InternalServerError");
      }

      browser.cookie = "";
      expect((yield* Effect.flip(api.blockClient({ client_id, blocked: true })))._tag).toBe(
        "Unauthenticated",
      );
      expect((yield* Effect.flip(api.revokeClient({ client_id })))._tag).toBe("Unauthenticated");
    }).pipe(Effect.provide(contractIssuer())),
  );

  it.live("client administration returns 404 for missing clients and 500 for failed writes", () =>
    Effect.gen(function* () {
      const browser = yield* Browser;
      const { sql } = yield* Database;
      const api = yield* apiClient(baseURL);
      yield* api.setupOwner({ email, password });

      const login = yield* Effect.promise(() =>
        browser.fetch(`${baseURL}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, password }),
        }),
      );

      expect(login.status).toBe(200);
      browser.cookie = login.headers
        .getSetCookie()
        .map((value) => value.split(";")[0])
        .join("; ");
      const missing = { client_id: "missing-client" };
      expect((yield* Effect.flip(api.revokeClient(missing)))._tag).toBe("ClientNotFound");

      for (const blocked of [true, false]) {
        expect((yield* Effect.flip(api.blockClient({ ...missing, blocked })))._tag).toBe(
          "ClientNotFound",
        );
      }

      const client = yield* api.createClient({
        client_name: "Failure test",
        redirect_uris: ["http://127.0.0.1:9876/callback"],
        resources: [],
        application_type: "native",
        token_endpoint_auth_method: "none",
      });

      const client_id = client.client_id;
      yield* sql`INSERT INTO oauthConsent (id, clientId, userId, scopes, createdAt, updatedAt) VALUES ('failure-consent', ${client_id}, ${yield* (yield* OwnerAccount).find()}, '[]', ${Date.now()}, ${Date.now()})`;
      yield* sql`CREATE TRIGGER fail_revoke BEFORE DELETE ON oauthConsent BEGIN SELECT RAISE(ABORT, 'injected database failure'); END`;
      expect((yield* Effect.flip(api.revokeClient({ client_id })))._tag).toBe(
        "InternalServerError",
      );
      expect((yield* Effect.flip(api.blockClient({ client_id, blocked: true })))._tag).toBe(
        "InternalServerError",
      );
      // Failed revocation also rolls back the disabled flag written by block.
      expect((yield* api.listClients()).clients[0]?.blocked).toBe(false);
      expect(yield* sql`SELECT id FROM oauthConsent WHERE clientId = ${client_id}`).toEqual([
        { id: "failure-consent" },
      ]);
    }).pipe(Effect.provide(contractIssuer())),
  );

  it.live(
    "malformed setup input is refused without reflecting the password or creating an owner",
    () =>
      Effect.gen(function* () {
        const browser = yield* Browser;

        const response = yield* Effect.promise(() =>
          browser.fetch(`${baseURL}/api/setupOwner`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ email, password: { sensitive: password } }),
          }),
        );

        expect(response.status).toBeGreaterThanOrEqual(400);
        expect(response.status).toBeLessThan(500);
        expect(yield* Effect.promise(() => response.text())).not.toContain(password);
        expect(yield* (yield* OwnerAccount).find()).toBeUndefined();
      }).pipe(Effect.provide(contractIssuer())),
  );
});
