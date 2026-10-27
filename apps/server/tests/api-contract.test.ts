import { it } from "@effect/vitest";
import {
  Http,
  ServiceUnavailable,
} from "@gjermundgaraba/clankerauth-admin-api";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { APIError } from "better-auth/api";
import { Context, Effect, Layer, Schema } from "effect";
import { FetchHttpClient } from "effect/http";
import { describe, expect, vi } from "vite-plus/test";

import { Issuer } from "../src/issuer/issuer.ts";
import { OwnerAccount } from "../src/owner/owner.ts";
import { peerHeader } from "../src/platform/node-http.ts";
import { Database } from "../src/platform/sqlite.ts";
import { administrationResource, decodeJson } from "./mcp-oauth-helper.ts";
import { signIn, testWebApplication, WebApplication } from "./test-issuer.ts";

const apiClient = (baseUrl: string) => ActionHttp.client(Http, { baseUrl });

const baseURL = "http://localhost:3000";

class Browser extends Context.Service<
  Browser,
  {
    readonly handle: (request: Request) => Promise<Response>;
    readonly fetch: typeof fetch;
    cookie: string;
  }
>()("api-contract.test/Browser") {}

const browserLayer = Layer.effect(
  Browser,
  Effect.gen(function* () {
    const handle = yield* WebApplication;

    const self: Browser["Service"] = {
      handle,
      fetch: async (input, init) => {
        const request = new Request(input, init);
        request.headers.set("origin", baseURL);
        request.headers.set("cookie", self.cookie);
        request.headers.set(peerHeader, "127.0.0.1");

        return await handle(request);
      },
      cookie: "",
    };

    return self;
  })
);

const contractIssuer = () =>
  Layer.mergeAll(
    FetchHttpClient.layer,
    Layer.effect(
      FetchHttpClient.Fetch,
      Effect.map(Browser, ({ fetch }) => fetch)
    )
  ).pipe(
    Layer.provideMerge(browserLayer),
    Layer.provideMerge(testWebApplication({ baseURL }))
  );

describe("API integration", () => {
  const email = "owner@example.internal";
  const password = "test-only owner password 8rS!";
  const resource = "https://example.internal/mcp";

  it.live(
    "generated client shares setup, owner authorization and client lifecycle",
    () =>
      Effect.gen(function* () {
        const browser = yield* Browser;
        const { sql } = yield* Database;
        const api = yield* apiClient(baseURL);
        expect(yield* api.setupStatus()).toStrictEqual({ required: true });
        expect(yield* api.setupOwner({ email, password })).toStrictEqual({
          created: true,
        });
        expect(yield* api.setupStatus()).toStrictEqual({ required: false });

        const repeatedSetup = yield* Effect.flip(
          api.setupOwner({ email, password })
        );

        expect(repeatedSetup._tag).toBe("OwnerExists");

        const anonymous = yield* Effect.flip(api.listClients());
        expect(anonymous._tag).toBe("Unauthenticated");

        browser.cookie = yield* signIn(browser.handle, baseURL, {
          email,
          password,
        });
        expect(browser.cookie).not.toBe("");

        const resourceInput = {
          identifier: resource,
          name: "Example MCP",
          scopes: ["example:read"],
        };

        expect((yield* api.listClients()).resources).toStrictEqual([
          administrationResource(baseURL),
        ]);
        yield* api.putResource(resourceInput);

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
        expect(listing.resources).toStrictEqual([
          administrationResource(baseURL),
          { ...resourceInput, builtIn: false },
        ]);
        expect(listing.clientAccess).toStrictEqual([
          { client_id: created.client_id, resource },
        ]);
        expect(listing.clients.map((client) => client.client_id)).toStrictEqual(
          [created.client_id]
        );
        expect(listing.clients[0]).not.toHaveProperty("client_secret");

        const updatedResource = {
          ...resourceInput,
          name: "Renamed MCP",
          scopes: ["example:read", "example:write"],
        };

        expect(
          (yield* api.putResource(updatedResource)).resource
        ).toStrictEqual(updatedResource);
        expect(
          yield* api.setClientAccess({
            client_id: created.client_id,
            resources: [],
          })
        ).toStrictEqual({
          clientAccess: [],
        });
        expect(
          yield* api.setClientAccess({
            client_id: created.client_id,
            resources: [resource],
          })
        ).toStrictEqual({
          clientAccess: [{ client_id: created.client_id, resource }],
        });

        const rotated = yield* api.rotateClientSecret({
          client_id: created.client_id,
        });

        expect(rotated.client_secret).toBeTypeOf("string");
        expect(rotated.client_secret).not.toBe(created.client_secret);

        expect(
          yield* api.revokeClient({ client_id: created.client_id })
        ).toStrictEqual({
          revoked: true,
        });
        expect(
          yield* api.blockClient({
            client_id: created.client_id,
            blocked: true,
          })
        ).toStrictEqual({
          blocked: true,
        });
        expect((yield* api.listClients()).clients[0]?.blocked).toBe(true);
        expect(
          (yield* api.putResource(updatedResource)).resource
        ).toStrictEqual(updatedResource);
        expect(
          yield* api.blockClient({
            client_id: created.client_id,
            blocked: false,
          })
        ).toStrictEqual({
          blocked: false,
        });
        expect((yield* api.listClients()).clients[0]?.blocked).toBe(false);
        yield* sql`UPDATE oauthClient SET redirectUris = ${JSON.stringify([42])} WHERE clientId = ${created.client_id}`;
        const invalidResponse = yield* Effect.flip(api.listClients());
        expect(invalidResponse._tag).toBe("InternalServerError");
        expect(
          yield* api.deleteClient({ client_id: created.client_id })
        ).toStrictEqual({
          deleted: true,
        });
        expect((yield* api.listClients()).clients).toStrictEqual([]);
        expect(
          yield* api.deleteResource({ identifier: resource })
        ).toStrictEqual({
          deleted: true,
        });
        expect((yield* api.listClients()).resources).toStrictEqual([
          administrationResource(baseURL),
        ]);
      }).pipe(Effect.provide(contractIssuer()))
  );

  it.live(
    "a session the provider cannot read answers the declared 503, which the client decodes",
    () =>
      Effect.gen(function* () {
        const browser = yield* Browser;
        const { auth, context } = yield* Issuer;
        vi.spyOn(auth.api, "getSession").mockRejectedValue(
          new APIError("SERVICE_UNAVAILABLE", {
            message: "Session store unavailable",
          })
        );
        browser.cookie = `${context.authCookies.sessionToken.name}=unreadable`;

        const response = yield* Effect.promise(
          async () =>
            await browser.fetch(`${baseURL}/api/listClients`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: "{}",
            })
        );

        expect(response.status).toBe(503);
        expect(yield* decodeJson(Schema.Json)(response)).toStrictEqual(
          yield* Schema.encodeEffect(ServiceUnavailable)(
            new ServiceUnavailable({ message: "Session store unavailable" })
          )
        );

        const failure = yield* Effect.flip(
          Effect.flatMap(apiClient(baseURL), (api) => api.listClients())
        );

        expect(failure).toBeInstanceOf(ServiceUnavailable);
      }).pipe(Effect.provide(contractIssuer()))
  );

  it.live(
    "getResource reads one resource and putResource creates it, then updates it",
    () =>
      Effect.gen(function* () {
        const browser = yield* Browser;
        const api = yield* apiClient(baseURL);
        yield* api.setupOwner({ email, password });
        browser.cookie = yield* signIn(browser.handle, baseURL, {
          email,
          password,
        });

        const missing = yield* Effect.flip(
          api.getResource({ identifier: resource })
        );

        expect(missing._tag).toBe("ResourceNotFound");
        expect(missing.message).toBe(`No resource ${resource} exists`);

        const first = {
          identifier: resource,
          name: "MCP",
          scopes: ["example:read"],
        };

        expect(yield* api.putResource(first)).toStrictEqual({
          resource: first,
          created: true,
        });
        expect(yield* api.getResource({ identifier: resource })).toStrictEqual({
          ...first,
          builtIn: false,
        });

        const second = {
          ...first,
          name: "Renamed",
          scopes: ["example:read", "example:write"],
        };

        expect(yield* api.putResource(second)).toStrictEqual({
          resource: second,
          created: false,
        });
        expect(yield* api.putResource(second)).toStrictEqual({
          resource: second,
          created: false,
        });
        expect((yield* api.listClients()).resources).toStrictEqual([
          administrationResource(baseURL),
          { ...second, builtIn: false },
        ]);

        expect(
          yield* api.getResource({ identifier: `${baseURL}/` })
        ).toStrictEqual(administrationResource(baseURL));
        expect(
          (yield* Effect.flip(
            api.putResource({
              identifier: `${baseURL}/`,
              name: "Mine",
              scopes: ["mine:read"],
            })
          ))._tag
        ).toBe("InvalidInput");
        expect(
          (yield* Effect.flip(
            api.putResource({ ...first, scopes: ["offline_access"] })
          ))._tag
        ).toBe("InvalidInput");
      }).pipe(Effect.provide(contractIssuer()))
  );

  it.live(
    "automatic clients are visible and manageable through the generated owner API",
    () =>
      Effect.gen(function* () {
        const browser = yield* Browser;
        const { sql } = yield* Database;
        const api = yield* apiClient(baseURL);
        yield* api.setupOwner({ email, password });

        browser.cookie = yield* signIn(browser.handle, baseURL, {
          email,
          password,
        });
        yield* api.putResource({
          identifier: resource,
          name: "MCP",
          scopes: ["example:read"],
        });

        const registration = yield* Effect.promise(
          async () =>
            await browser.handle(
              new Request(`${baseURL}/api/auth/oauth2/register`, {
                method: "POST",
                headers: {
                  "content-type": "application/json",
                  [peerHeader]: "127.0.0.1",
                },
                body: JSON.stringify({
                  client_name: "Automatic MCP",
                  redirect_uris: ["http://127.0.0.1:9876/callback"],
                  token_endpoint_auth_method: "none",
                  grant_types: ["authorization_code", "refresh_token"],
                }),
              })
            )
        );

        expect(registration.status).toBe(201);
        expect(registration.headers.get("access-control-allow-origin")).toBe(
          "*"
        );
        expect(
          registration.headers.has("access-control-allow-credentials")
        ).toBe(false);

        const preflight = yield* Effect.promise(
          async () =>
            await browser.handle(
              new Request(`${baseURL}/api/auth/oauth2/register`, {
                method: "OPTIONS",
                headers: {
                  origin: "https://mcp-client.example",
                  "access-control-request-method": "POST",
                  "access-control-request-headers": "content-type",
                },
              })
            )
        );

        expect(preflight.status).toBe(204);
        expect(preflight.headers.get("access-control-allow-methods")).toContain(
          "POST"
        );

        const { client_id } = yield* decodeJson(
          Schema.Struct({ client_id: Schema.String })
        )(registration);

        const listing = yield* api.listClients();
        expect(listing.clients).toHaveLength(1);
        expect(listing.clients[0]).toMatchObject({
          client_id,
          onboarding: "dcr",
          blocked: false,
        });
        expect(listing.clients[0]).not.toHaveProperty("client_secret");
        expect(listing.clientAccess).toStrictEqual([]);
        expect(listing.connections).toStrictEqual([]);
        expect(
          (yield* Effect.flip(
            api.setClientAccess({ client_id, resources: [] })
          ))._tag
        ).toBe("ClientIsAutomatic");
        expect(
          (yield* Effect.flip(
            api.updateClient({
              client_id,
              client_name: "Renamed",
              redirect_uris: ["http://127.0.0.1:9876/callback"],
              application_type: "native",
            })
          ))._tag
        ).toBe("ClientIsAutomatic");
        expect(yield* api.revokeClient({ client_id })).toStrictEqual({
          revoked: true,
        });
        expect(
          yield* api.blockClient({ client_id, blocked: true })
        ).toStrictEqual({
          blocked: true,
        });
        expect((yield* api.listClients()).clients[0]?.blocked).toBe(true);
        expect(
          yield* api.blockClient({ client_id, blocked: false })
        ).toStrictEqual({
          blocked: false,
        });
        expect((yield* api.listClients()).clients[0]?.blocked).toBe(false);
        expect(
          yield* api.deleteResource({ identifier: resource })
        ).toStrictEqual({
          deleted: true,
        });
        expect(
          (yield* api.listClients()).resources.map((entry) => entry.identifier)
        ).toStrictEqual([`${baseURL}/`]);

        yield* sql`UPDATE oauthClient SET clientDiscoveryId = 'cimd', name = NULL, tokenEndpointAuthMethod = NULL, applicationType = NULL, scopes = NULL, grantTypes = NULL WHERE clientId = ${client_id}`;
        expect((yield* api.listClients()).clients).toStrictEqual([
          {
            client_id,
            onboarding: "cimd",
            blocked: false,
            redirect_uris: ["http://127.0.0.1:9876/callback"],
            application_type: null,
            client_name: undefined,
            scope: undefined,
            grant_types: undefined,
            token_endpoint_auth_method: undefined,
          },
        ]);

        for (const invalidRedirects of ["null", "[42]"]) {
          yield* sql`UPDATE oauthClient SET redirectUris = ${invalidRedirects} WHERE clientId = ${client_id}`;
          expect((yield* Effect.flip(api.listClients()))._tag).toBe(
            "InternalServerError"
          );
        }

        browser.cookie = "";
        expect(
          (yield* Effect.flip(api.blockClient({ client_id, blocked: true })))
            ._tag
        ).toBe("Unauthenticated");
        expect((yield* Effect.flip(api.revokeClient({ client_id })))._tag).toBe(
          "Unauthenticated"
        );
      }).pipe(Effect.provide(contractIssuer()))
  );

  it.live(
    "client administration returns 404 for missing clients and 500 for failed writes",
    () =>
      Effect.gen(function* () {
        const browser = yield* Browser;
        const { sql } = yield* Database;
        const api = yield* apiClient(baseURL);
        yield* api.setupOwner({ email, password });

        browser.cookie = yield* signIn(browser.handle, baseURL, {
          email,
          password,
        });
        const missing = { client_id: "missing-client" };
        expect((yield* Effect.flip(api.revokeClient(missing)))._tag).toBe(
          "ClientNotFound"
        );

        for (const blocked of [true, false]) {
          expect(
            (yield* Effect.flip(api.blockClient({ ...missing, blocked })))._tag
          ).toBe("ClientNotFound");
        }

        const client = yield* api.createClient({
          client_name: "Failure test",
          redirect_uris: ["http://127.0.0.1:9876/callback"],
          resources: [],
          application_type: "native",
          token_endpoint_auth_method: "none",
        });

        const { client_id } = client;
        yield* sql`INSERT INTO oauthConsent (id, clientId, userId, scopes, createdAt, updatedAt) VALUES ('failure-consent', ${client_id}, ${yield* (yield* OwnerAccount).find}, '[]', ${Date.now()}, ${Date.now()})`;
        yield* sql`CREATE TRIGGER fail_revoke BEFORE DELETE ON oauthConsent BEGIN SELECT RAISE(ABORT, 'injected database failure'); END`;
        expect((yield* Effect.flip(api.revokeClient({ client_id })))._tag).toBe(
          "InternalServerError"
        );
        expect(
          (yield* Effect.flip(api.blockClient({ client_id, blocked: true })))
            ._tag
        ).toBe("InternalServerError");
        expect((yield* api.listClients()).clients[0]?.blocked).toBe(false);
        expect(
          (yield* sql`SELECT id FROM oauthConsent WHERE clientId = ${client_id}`).map(
            (row) => ({ ...row })
          )
        ).toStrictEqual([{ id: "failure-consent" }]);
      }).pipe(Effect.provide(contractIssuer()))
  );

  it.live(
    "malformed setup input is refused without reflecting the password or creating an owner",
    () =>
      Effect.gen(function* () {
        const browser = yield* Browser;

        const response = yield* Effect.promise(
          async () =>
            await browser.fetch(`${baseURL}/api/setupOwner`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                email,
                password: { sensitive: password },
              }),
            })
        );

        expect(response.status).toBeGreaterThanOrEqual(400);
        expect(response.status).toBeLessThan(500);
        expect(
          yield* Effect.promise(async () => await response.text())
        ).not.toContain(password);
        expect(yield* (yield* OwnerAccount).find).toBeUndefined();
      }).pipe(Effect.provide(contractIssuer()))
  );
});
