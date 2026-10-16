import { it } from "@effect/vitest";
import { Context, Effect, Exit, Layer } from "effect";
import {
  ClientIsAutomatic,
  ClientNotFound,
  CurrentOwner,
} from "@gjermundgaraba/clankerauth-admin-api";
import { beforeEach, expect } from "vite-plus/test";
import { createHash } from "node:crypto";
import { issuerGeneration, signIn, testIssuer, testSettings } from "../test-issuer.ts";
import { peerHeader } from "../../src/platform/node-http.ts";
import { Database } from "../../src/platform/sqlite.ts";
import { OwnerAccount } from "../../src/owner/owner.ts";
import { Issuer } from "../../src/issuer/issuer.ts";
import { ResourceCatalog } from "../../src/resources/catalog.ts";
import { Resources } from "../../src/resources/resources.ts";
import { Clients } from "../../src/clients/clients.ts";

const baseURL = "http://localhost:4183";

const resource = "https://resource.example/mcp";

const clientId = "https://client.example/oauth/metadata.json";

const callback = "http://127.0.0.1:4184/callback";

const verifier = "a".repeat(43);

const owner = { email: "owner@example.com", password: "test-password-long-enough" };

type AuthRequestBody = { readonly [key: string]: string | boolean | null | readonly string[] };

type ClientMetadata = {
  client_id: string;
  client_name?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  grant_types?: string[];
  response_types?: string[];
};

let fetches: number;

let metadata: ClientMetadata;

let metadataCacheControl: string;

const cimdTransport = async () => {
  fetches++;

  return Response.json(metadata, { headers: { "cache-control": metadataCacheControl } });
};

beforeEach(() => {
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
});

class OwnerCookie extends Context.Service<OwnerCookie, string>()("clients.test/OwnerCookie") {}

const ownerHeaders = Effect.map(OwnerCookie, (cookie) => new Headers({ cookie, origin: baseURL }));

const asOwner = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  Effect.gen(function* () {
    const owners = yield* OwnerAccount;
    const userId = yield* owners.find();

    if (!userId) return yield* Effect.die("Missing test owner");

    return yield* effect.pipe(
      Effect.provideService(CurrentOwner, owners.caller(userId, owner.email, true)),
      Effect.scoped,
    );
  });

const request = (path: string, body?: AuthRequestBody, cookie?: string) =>
  Effect.gen(function* () {
    const headers = new Headers({ [peerHeader]: "127.0.0.1" });

    if (body !== undefined)
      headers.set(
        "content-type",
        path === "/oauth2/token" ? "application/x-www-form-urlencoded" : "application/json",
      );

    if (cookie !== undefined) {
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

    const { auth } = yield* Issuer;

    return yield* Effect.promise(() =>
      auth.handler(new Request(`${baseURL}/api/auth${path}`, init)),
    );
  });

const ownerRequest = (path: string, body?: AuthRequestBody) =>
  Effect.flatMap(OwnerCookie, (cookie) => request(path, body, cookie));

const json = (response: Response) => Effect.promise(() => response.json());

const text = (response: Response) => Effect.promise(() => response.clone().text());

function authorization(
  id: string,
  identifier = resource,
  port = 4184,
  scope = "offline_access resource:read",
) {
  return (
    "/oauth2/authorize?" +
    new URLSearchParams({
      client_id: id,
      redirect_uri: `http://127.0.0.1:${port}/callback`,
      response_type: "code",
      scope,
      resource: identifier,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      state: "clients-test",
    })
  );
}

const register = Effect.gen(function* () {
  const response = yield* request("/oauth2/register", {
    client_name: "Dynamic client",
    redirect_uris: [callback],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });

  expect(response.status, yield* text(response)).toBe(201);

  return yield* json(response);
});

const grant = (id: string, identifier = resource, scope?: string) =>
  Effect.gen(function* () {
    const response = yield* ownerRequest(authorization(id, identifier, 4184, scope));
    expect(response.status, yield* text(response)).toBe(302);
    const location = new URL(response.headers.get("location")!, baseURL);
    expect(location.pathname).toBe("/consent");

    const consent = yield* ownerRequest("/oauth2/consent", {
      accept: true,
      oauth_query: location.search.slice(1),
    });

    expect(consent.status, yield* text(consent)).toBe(200);
    const code = new URL((yield* json(consent)).url).searchParams.get("code");

    const tokens = yield* request("/oauth2/token", {
      grant_type: "authorization_code",
      client_id: id,
      code,
      code_verifier: verifier,
      redirect_uri: callback,
      resource: identifier,
    });

    expect(tokens.status, yield* text(tokens)).toBe(200);

    return yield* json(tokens);
  });

const refresh = (id: string, token: string, identifier = resource) =>
  request("/oauth2/token", {
    grant_type: "refresh_token",
    client_id: id,
    refresh_token: token,
    resource: identifier,
  });

const blocked = (id: string) =>
  Effect.flatMap(
    Database,
    ({ sql }) => sql`SELECT disabled FROM oauthClient WHERE clientId = ${id}`,
  );

const consentRequired = (id: string, identifier = resource, scope?: string) =>
  Effect.map(
    ownerRequest(authorization(id, identifier, 4184, scope)),
    (response) => response.headers.get("location") ?? "",
  );

const createResource = (identifier: string, name: string, scopes: ReadonlyArray<string>) =>
  Effect.flatMap(Resources, (resources) =>
    asOwner(resources.put({ identifier, name, scopes: [...scopes] })),
  );

const second = "https://second.example/mcp";

const addSecond = createResource(second, "Second", ["second:read"]);

const managed = Effect.gen(function* () {
  const { auth } = yield* Issuer;
  const headers = yield* ownerHeaders;

  const client = yield* Effect.promise(() =>
    auth.api.adminCreateOAuthClient({
      headers,
      body: {
        client_name: "Managed client",
        redirect_uris: [callback],
        application_type: "native",
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        scope: "offline_access resource:read",
        skip_consent: true,
      },
    }),
  );

  yield* (yield* Resources).setAccess({ client_id: client.client_id, resources: [resource] });

  return client.client_id;
});

const ownerWithResource = Layer.effect(
  OwnerCookie,
  Effect.gen(function* () {
    yield* (yield* OwnerAccount).create(owner);
    const { auth } = yield* Issuer;
    const cookie = yield* signIn((request) => auth.handler(request), baseURL, owner);
    yield* createResource(resource, "Test resource", ["resource:read"]).pipe(
      Effect.provideService(OwnerCookie, cookie),
    );

    return cookie;
  }),
);

const clientsIssuer = () =>
  ownerWithResource.pipe(Layer.provideMerge(testIssuer({ baseURL }, cimdTransport)));

it.live("DCR infers native callbacks, keeps PKCE and consent, and revocation ends refresh", () =>
  Effect.gen(function* () {
    const client = yield* register;
    expect(client.application_type).toBe("native");
    const alternate = yield* ownerRequest(authorization(client.client_id, resource, 4999));
    expect(alternate.headers.get("location")).toContain("/consent");
    const tokens = yield* grant(client.client_id);
    expect(tokens.access_token).toBeTypeOf("string");
    expect(yield* (yield* Clients).revoke({ client_id: client.client_id })).toEqual({
      revoked: true,
    });
    expect((yield* refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
    expect(yield* consentRequired(client.client_id)).toContain("/consent");
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live("DCR cannot self-assert consent bypass, and its resource list is ignored", () =>
  Effect.gen(function* () {
    expect(
      (yield* request("/oauth2/register", {
        client_name: "Untrusted",
        redirect_uris: [callback],
        token_endpoint_auth_method: "none",
        skip_consent: true,
      })).status,
    ).toBe(400);
    expect(
      (yield* request("/oauth2/register", {
        client_name: "Untrusted",
        redirect_uris: [callback],
        token_endpoint_auth_method: "none",
        resources: [resource, "https://unconfigured.example/mcp"],
      })).status,
    ).toBe(201);
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live.each(["dcr", "cimd"])(
  "%s clients may ask for resources added later, and deletion revokes dependent grants",
  (source) =>
    Effect.gen(function* () {
      const client = source === "dcr" ? yield* register : { client_id: clientId };
      const tokens = yield* grant(client.client_id);
      yield* addSecond;
      expect(
        yield* consentRequired(client.client_id, second, "offline_access second:read"),
      ).toContain("/consent");
      yield* asOwner((yield* Resources).delete({ identifier: resource }));
      expect((yield* refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
      expect(yield* consentRequired(client.client_id)).not.toContain("/consent");
    }).pipe(Effect.provide(clientsIssuer())),
);

it.live("automatic clients have no configurable resource access", () =>
  Effect.gen(function* () {
    const client = yield* register;

    expect(
      yield* Effect.flip(
        (yield* Resources).setAccess({ client_id: client.client_id, resources: [] }),
      ),
    ).toEqual(ClientIsAutomatic.of(client.client_id));
    expect(yield* (yield* ResourceCatalog).access()).toEqual([]);
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live("blocking uses the provider's disabled flag and survives CIMD metadata rediscovery", () =>
  Effect.gen(function* () {
    const clients = yield* Clients;
    expect(yield* consentRequired(clientId)).toContain("/consent");
    expect(fetches).toBe(1);
    const tokens = yield* grant(clientId);
    expect(yield* clients.block({ client_id: clientId, blocked: true })).toEqual({
      blocked: true,
    });
    expect(yield* blocked(clientId)).toEqual([{ disabled: 1 }]);
    expect((yield* refresh(clientId, tokens.refresh_token)).status).toBe(400);
    // why: outlasts the metadata cache, so the next authorization fetches the document again
    yield* Effect.sleep("1100 millis");
    expect(yield* consentRequired(clientId)).not.toContain("/consent");
    expect(fetches).toBe(2);
    expect(yield* blocked(clientId)).toEqual([{ disabled: 1 }]);
    expect(yield* clients.block({ client_id: clientId, blocked: false })).toEqual({
      blocked: false,
    });
    expect(yield* consentRequired(clientId)).toContain("/consent");
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live("blocking a dynamically registered client rejects authorization until unblocked", () =>
  Effect.gen(function* () {
    const clients = yield* Clients;
    const client = yield* register;
    yield* clients.block({ client_id: client.client_id, blocked: true });
    const refused = yield* ownerRequest(authorization(client.client_id));
    expect(refused.headers.get("location") ?? "").not.toContain("/consent");
    yield* clients.block({ client_id: client.client_id, blocked: false });
    expect(yield* consentRequired(client.client_id)).toContain("/consent");
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live("block and revoke report unknown clients", () =>
  Effect.gen(function* () {
    const clients = yield* Clients;
    const missing = ClientNotFound.of("missing");
    expect(yield* Effect.flip(clients.revoke({ client_id: "missing" }))).toEqual(missing);
    expect(yield* Effect.flip(clients.block({ client_id: "missing", blocked: true }))).toEqual(
      missing,
    );
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live("initialization is repeatable and refresh grants survive a reopen", () =>
  Effect.gen(function* () {
    const { client, tokens } = yield* Effect.gen(function* () {
      const client = yield* register;

      return { client, tokens: yield* grant(client.client_id) };
    }).pipe(
      Effect.provide(ownerWithResource.pipe(Layer.provideMerge(issuerGeneration(cimdTransport)))),
    );

    const refreshed = yield* refresh(client.client_id, tokens.refresh_token).pipe(
      Effect.provide(issuerGeneration(cimdTransport)),
    );

    expect(refreshed.status).toBe(200);
  }).pipe(Effect.provide(testSettings({ baseURL }))),
);

it.live("CIMD rejects malformed metadata before persisting a client", () =>
  Effect.gen(function* () {
    const { sql } = yield* Database;
    metadata = {
      client_id: clientId,
      redirect_uris: [callback],
      token_endpoint_auth_method: "none",
    };
    expect(yield* consentRequired(clientId)).not.toContain("/consent");
    expect(yield* sql`SELECT clientId FROM oauthClient WHERE clientId = ${clientId}`).toEqual([]);
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live("revoking one resource leaves the client's other authorization", () =>
  Effect.gen(function* () {
    const clients = yield* Clients;
    yield* addSecond;
    const client = yield* register;
    const tokens = yield* grant(client.client_id);

    const response = yield* ownerRequest(
      authorization(client.client_id, second, 4184, "offline_access second:read"),
    );

    const location = new URL(response.headers.get("location")!, baseURL);

    const consent = yield* ownerRequest("/oauth2/consent", {
      accept: true,
      oauth_query: location.search.slice(1),
    });

    expect(consent.status, yield* text(consent)).toBe(200);
    const listed = yield* clients.connections();
    expect(listed.map((connection) => [connection.resource, connection.scopes])).toEqual([
      [resource, ["resource:read"]],
      [second, ["second:read"]],
    ]);
    expect(listed[0]?.approvedAt).not.toBeNull();
    expect(listed[0]?.refreshedAt).not.toBeNull();
    expect(listed[1]?.refreshedAt).toBeNull();

    yield* clients.revoke({ client_id: client.client_id, resource: second });
    expect((yield* clients.connections()).map((c) => c.resource)).toEqual([resource]);
    expect((yield* refresh(client.client_id, tokens.refresh_token)).status).toBe(200);
    expect(
      yield* consentRequired(client.client_id, second, "offline_access second:read"),
    ).toContain("/consent");
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live("the owner can delete an automatic client, which may register again", () =>
  Effect.gen(function* () {
    const clients = yield* Clients;
    const client = yield* register;
    const tokens = yield* grant(client.client_id);
    expect(yield* clients.delete({ client_id: client.client_id })).toEqual({ deleted: true });
    expect((yield* refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
    expect(yield* clients.connections()).toEqual([]);
    expect(yield* Effect.flip(clients.delete({ client_id: client.client_id }))).toEqual(
      ClientNotFound.of(client.client_id),
    );

    expect(yield* consentRequired(clientId)).toContain("/consent");
    yield* clients.delete({ client_id: clientId });
    expect(yield* consentRequired(clientId)).toContain("/consent");
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live("a recreated resource does not revive authorization given for the deleted one", () =>
  Effect.gen(function* () {
    const client = yield* register;
    const tokens = yield* grant(client.client_id);
    yield* asOwner((yield* Resources).delete({ identifier: resource }));
    yield* createResource(resource, "Test resource", ["resource:read"]);
    expect((yield* refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
    expect(yield* consentRequired(client.client_id)).toContain("/consent");
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live("creating a resource clears authorization a failed deletion left behind", () =>
  Effect.gen(function* () {
    const { sql } = yield* Database;
    const client = yield* register;
    const tokens = yield* grant(client.client_id);
    yield* sql`CREATE TRIGGER fail_clear BEFORE DELETE ON oauthConsent BEGIN SELECT RAISE(ABORT, 'injected database failure'); END`;
    expect(
      Exit.isFailure(
        yield* Effect.exit(asOwner((yield* Resources).delete({ identifier: resource }))),
      ),
    ).toBe(true);
    yield* sql`DROP TRIGGER fail_clear`;
    expect(yield* (yield* ResourceCatalog).get(resource)).toBeUndefined();

    yield* createResource(resource, "Test resource", ["resource:read"]);
    expect((yield* refresh(client.client_id, tokens.refresh_token)).status).toBe(400);
    expect(yield* consentRequired(client.client_id)).toContain("/consent");
  }).pipe(Effect.provide(clientsIssuer())),
);

it.live(
  "a managed client, which skips consent, shows a connection while it holds a refresh token",
  () =>
    Effect.gen(function* () {
      const clients = yield* Clients;
      const id = yield* managed;
      expect(yield* clients.connections()).toEqual([]);

      const response = yield* ownerRequest(authorization(id));
      expect(response.status, yield* text(response)).toBe(302);
      const code = new URL(response.headers.get("location")!).searchParams.get("code");
      expect(code).toBeTypeOf("string");

      const tokens = yield* request("/oauth2/token", {
        grant_type: "authorization_code",
        client_id: id,
        code: code!,
        code_verifier: verifier,
        redirect_uri: callback,
        resource,
      });

      expect(tokens.status, yield* text(tokens)).toBe(200);
      const [connection, ...rest] = yield* clients.connections();
      expect(rest).toEqual([]);
      expect(connection).toMatchObject({
        client_id: id,
        resource,
        scopes: ["resource:read"],
        approvedAt: null,
      });
      expect(connection?.refreshedAt).not.toBeNull();

      yield* clients.revoke({ client_id: id, resource: resource });
      expect(yield* clients.connections()).toEqual([]);
    }).pipe(Effect.provide(clientsIssuer())),
);
