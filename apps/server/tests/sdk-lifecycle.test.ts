/** The package against the real server: first-party login, verification, API keys, logout. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "vite-plus/test";
import { nodeHandler } from "../src/app.ts";
import { initialize, openAuth } from "../src/auth.ts";
import { testSettings } from "./settings.ts";
import { createNodeServer } from "../src/node-http.ts";
import { Effect, Exit, Redacted, Schema, Scope } from "effect";
import {
  BrowserSession,
  SessionStore,
  Unauthorized,
  Forbidden,
} from "@gjermundgaraba/clankerauth-sdk";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";
import { LoginResponse, memoryStore, run, webBrowser, withHttp } from "./sdk-support.ts";

const origin = "http://127.0.0.1:7337";

const resource = `${origin}/api`;

const browserCallback = `${origin}/notes/oauth/complete`;

const owner = { email: "owner@example.internal", password: randomBytes(24).toString("base64url") };

const ClientCreated = Schema.Struct({ client_id: Schema.String, client_secret: Schema.String });

const SessionBody = Schema.Struct({ subject: Schema.String });

const ApiKeyCreated = Schema.Struct({ key: Schema.String, keyId: Schema.String });

type CallBody =
  | { readonly email: string; readonly password: string }
  | {
      readonly identifier: string;
      readonly name: string;
      readonly scopes: readonly string[];
    }
  | {
      readonly client_name: string;
      readonly redirect_uris: readonly string[];
      readonly resources: readonly string[];
      readonly token_endpoint_auth_method: string;
      readonly application_type: string;
    }
  | {
      readonly name: string;
      readonly permissions: { readonly [identifier: string]: readonly string[] };
      readonly expiresAt: null;
    }
  | { readonly keyId: string; readonly enabled: boolean };

const startServer = async () => {
  const directory = await mkdtemp(join(tmpdir(), "clankerauth-sdk-"));

  let serve = (_incoming: IncomingMessage, outgoing: ServerResponse) => {
    outgoing.writeHead(503).end();
  };

  const server = createNodeServer((incoming, outgoing) => {
    serve(incoming, outgoing);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();

  if (address === null || !(address instanceof Object) || !("port" in address))
    throw new Error("Expected TCP listener");
  const { port } = address;
  const url = `http://127.0.0.1:${port}`;

  const service = await Effect.runPromise(
    openAuth(testSettings({ baseURL: url, database: join(directory, "issuer.sqlite"), port })),
  );

  await Effect.runPromise(initialize(service));
  const httpScope = Scope.makeUnsafe();
  serve = await Effect.runPromise(
    nodeHandler(service).pipe(Effect.provideService(Scope.Scope, httpScope)),
  );
  const cookies = new Map<string, string>();
  const cookieHeader = () => [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");

  const call = async (path: string, body?: CallBody) => {
    const headers = new Headers({ origin: url, cookie: cookieHeader() });

    if (body) headers.set("content-type", "application/json");

    const response = await fetch(new URL(path, url), {
      method: body ? "POST" : "GET",
      redirect: "manual",
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      cookies.set(pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1));
    }

    return response;
  };

  /** A top-level browser navigation: no Origin, not a CORS fetch, so the issuer answers with 302. */
  const navigate = (target: string) =>
    new Promise<{ status: number; location: string }>((resolve, reject) => {
      const outgoing = httpRequest(
        target,
        { headers: { accept: "text/html", cookie: cookieHeader() } },
        (incoming) => {
          incoming.resume();
          incoming.on("end", () =>
            resolve({
              status: incoming.statusCode ?? 0,
              location: incoming.headers.location ?? "",
            }),
          );
        },
      );

      outgoing.on("error", reject);
      outgoing.end();
    });

  const close = async () => {
    await new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });
    await Effect.runPromise(Scope.close(httpScope, Exit.void));
    await service.close();
    await rm(directory, { recursive: true, force: true });
  };

  return { url, issuer: `${url}/api/auth`, call, navigate, close };
};

test("first-party browser login, verification of tokens and keys, and logout against the real issuer", async () => {
  const issuer = await startServer();

  try {
    assert.equal((await issuer.call("/api/issuer/setupOwner", owner)).status, 201);
    assert.equal((await issuer.call("/api/auth/sign-in/email", owner)).status, 200);

    assert.equal(
      (
        await issuer.call("/api/administration/createResource", {
          identifier: resource,
          name: "Notes",
          scopes: ["notes:read", "notes:write"],
        })
      ).status,
      201,
    );

    const registration = await issuer.call("/api/administration/createClient", {
      client_name: "Notes web",
      redirect_uris: [browserCallback],
      resources: [resource],
      token_endpoint_auth_method: "client_secret_basic",
      // Loopback HTTP redirects are only valid for native clients; production uses HTTPS web clients.
      application_type: "native",
    });

    assert.equal(registration.status, 201, await registration.clone().text());
    const client = Schema.decodeUnknownSync(ClientCreated)(await registration.json());

    const { verifier } = await run(
      withHttp(
        Resource.make({
          issuer: issuer.issuer,
          resource,
          requiredScopes: ["notes:read"],
          scopes: ["notes:read", "notes:write"],
        }),
      ),
    );

    const { store } = memoryStore();

    const browser = webBrowser(
      await run(
        withHttp(
          BrowserSession.make({
            issuer: issuer.issuer,
            clientId: client.client_id,
            clientSecret: Redacted.make(client.client_secret),
            callbackUrl: browserCallback,
            resource,
            scopes: ["notes:read", "notes:write"],
            secret: Redacted.make(randomBytes(32).toString("hex")),
            cookie: { name: "notes" },
            verifyToken: verifier.verifyToken,
          }).pipe(Effect.provideService(SessionStore, store)),
        ),
      ),
    );

    // Login: the signed-in owner is sent straight back with a code, with no consent step.
    const started = await browser.login(
      new Request(`${origin}/auth/browser/login`, {
        method: "POST",
        headers: { origin, "content-type": "application/json" },
        body: JSON.stringify({ returnTo: "/notes?x=1#top" }),
      }),
    );

    assert.equal(started.status, 200, await started.clone().text());
    const transaction = started.headers.get("set-cookie")?.split(";")[0] ?? "";
    const startedBody = Schema.decodeUnknownSync(LoginResponse)(await started.json());
    const authorization = startedBody.url;
    const redirected = await issuer.navigate(authorization);
    assert.equal(redirected.status, 302);
    const callbackUrl = new URL(redirected.location);
    assert.equal(`${callbackUrl.origin}${callbackUrl.pathname}`, browserCallback);
    assert.equal(callbackUrl.searchParams.get("iss"), issuer.issuer);
    assert(callbackUrl.searchParams.get("code"));

    const callback = await browser.callback(
      new Request(callbackUrl, { headers: { cookie: transaction } }),
    );

    assert.equal(callback.status, 302, await callback.clone().text());
    assert.equal(callback.headers.get("location"), `${origin}/notes?x=1#top`);
    const cookie = callback.headers.getSetCookie()[0]!.split(";")[0]!;
    assert.match(cookie, /^notes_session=/u);

    // The session yields an access token the verifier accepts for this resource only.
    const token = await browser.accessToken(new Request(`${origin}/api`, { headers: { cookie } }));
    const principal = await run(verifier.verify(`Bearer ${token}`));
    // Tokens carry protocol scopes too; resource servers check for the scopes they define.
    assert.deepEqual(principal.scopes, ["openid", "offline_access", "notes:read", "notes:write"]);
    assert.deepEqual(principal.actor, { kind: "client", clientId: client.client_id });

    const { verifier: other } = await run(
      withHttp(Resource.make({ issuer: issuer.issuer, resource: `${origin}/mcp`, scopes: [] })),
    );

    await assert.rejects(run(other.verifyToken(token)), (error) => error instanceof Unauthorized);

    const session = await browser.session(
      new Request(`${origin}/auth/browser/session`, {
        method: "POST",
        headers: { origin, cookie, "content-type": "application/json" },
        body: "{}",
      }),
    );

    assert.equal(session.status, 200);
    const sessionBody = Schema.decodeUnknownSync(SessionBody)(await session.json());
    assert.equal(sessionBody.subject, principal.subject);

    // API keys are verified online with their granted scopes and the key as actor.
    const created = await issuer.call("/api/administration/createApiKey", {
      name: "Backup script",
      permissions: { [resource]: ["notes:read"] },
      expiresAt: null,
    });

    assert.equal(created.status, 201, await created.clone().text());
    const createdBody = Schema.decodeUnknownSync(ApiKeyCreated)(await created.json());
    const { key, keyId } = createdBody;
    const machine = await run(verifier.verify(`Bearer ${key}`));
    assert.equal(machine.subject, principal.subject);
    assert.deepEqual(machine.scopes, ["notes:read"]);
    assert.deepEqual(machine.actor, { kind: "key", keyId });
    await assert.rejects(run(other.verifyToken(key)), (error) => error instanceof Forbidden);
    assert.equal(
      (await issuer.call("/api/administration/updateApiKey", { keyId, enabled: false })).status,
      200,
    );
    await assert.rejects(run(verifier.verifyToken(key)), (error) => error instanceof Unauthorized);

    // Logout revokes the refresh token at the issuer and ends the local session.
    const logout = await browser.logout(
      new Request(`${origin}/auth/browser/logout`, {
        method: "POST",
        headers: { origin, cookie, "content-type": "application/json" },
        body: "{}",
      }),
    );

    assert.equal(logout.status, 200);
    await assert.rejects(
      browser.accessToken(new Request(`${origin}/api`, { headers: { cookie } })),
      (error) => error instanceof Unauthorized,
    );
  } finally {
    await issuer.close();
  }
});
