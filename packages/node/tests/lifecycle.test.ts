/** The package against the real server: first-party login, verification, API keys, logout. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "vite-plus/test";
import { application } from "../../../apps/server/src/app.ts";
import { initialize, openAuth } from "../../../apps/server/src/auth.ts";
import { createNodeServer, nodeListener } from "../../../apps/server/src/node-http.ts";
import {
  AuthError,
  createBrowserSession,
  createVerifier,
  type BrowserSessionStore,
} from "../src/index.ts";

const origin = "http://127.0.0.1:7337";
const resource = `${origin}/api`;
const owner = { email: "owner@example.internal", password: randomBytes(24).toString("base64url") };

const startServer = async () => {
  const directory = await mkdtemp(join(tmpdir(), "clankerauth-node-"));
  let serve = async (_incoming: IncomingMessage, outgoing: ServerResponse) => {
    outgoing.writeHead(503).end();
  };
  const server = createNodeServer((incoming, outgoing) => {
    void serve(incoming, outgoing).catch(() => {
      if (!outgoing.headersSent) outgoing.writeHead(500).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${port}`;
  const service = await openAuth({
    baseURL: url,
    secret: randomBytes(32).toString("hex"),
    database: join(directory, "issuer.sqlite"),
    host: "127.0.0.1",
    port,
  });
  await initialize(service);
  const handler = application(service);
  serve = nodeListener(handler, url);
  const cookies = new Map<string, string>();
  const cookieHeader = () => [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  const call = async (path: string, body?: unknown) => {
    const response = await fetch(new URL(path, url), {
      method: body ? "POST" : "GET",
      redirect: "manual",
      headers: {
        origin: url,
        cookie: cookieHeader(),
        ...(body ? { "content-type": "application/json" } : {}),
      },
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
    await handler.dispose();
    await service.close();
    await rm(directory, { recursive: true, force: true });
  };
  return { url, issuer: `${url}/api/auth`, call, navigate, close };
};

test("first-party browser login, verification of tokens and keys, and logout against the real issuer", async () => {
  const issuer = await startServer();
  try {
    assert.equal((await issuer.call("/api/setupOwner", owner)).status, 201);
    assert.equal((await issuer.call("/api/auth/sign-in/email", owner)).status, 200);
    assert.equal(
      (
        await issuer.call("/api/createResource", {
          identifier: resource,
          name: "Notes",
          scopes: ["notes:read", "notes:write"],
        })
      ).status,
      201,
    );
    const registration = await issuer.call("/api/createClient", {
      name: "Notes web",
      redirect: `${origin}/auth/callback`,
      resources: [resource],
      confidential: true,
      // Loopback HTTP redirects are only valid for native clients; production uses HTTPS web clients.
      native: true,
    });
    assert.equal(registration.status, 201, await registration.clone().text());
    const client = (await registration.json()) as { client_id: string; client_secret: string };
    const failures: string[] = [];
    const verifier = createVerifier({
      issuer: issuer.issuer,
      resource,
      requiredScopes: ["notes:read"],
      onFailure: (operation) => {
        failures.push(operation);
      },
    });
    const rows = new Map<string, { payload: string; expires: number }>();
    const store: BrowserSessionStore = {
      get: async (id) => rows.get(id),
      put: async (id, payload, expires) => {
        rows.set(id, { payload, expires });
      },
      delete: async (id) => {
        rows.delete(id);
      },
      sweep: async (now) => {
        for (const [id, row] of rows) if (row.expires <= now) rows.delete(id);
      },
    };
    const browser = createBrowserSession({
      issuer: issuer.issuer,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      origin,
      resource,
      scopes: ["notes:read", "notes:write"],
      secret: randomBytes(32).toString("hex"),
      store,
      cookie: { name: "notes" },
      verifyToken: verifier.verifyToken,
      onFailure: (operation) => {
        failures.push(operation);
      },
    });

    // Login: the signed-in owner is sent straight back with a code, with no consent step.
    const started = await browser.login(
      new Request(`${origin}/auth/login`, {
        method: "POST",
        headers: { origin, "content-type": "application/json" },
        body: JSON.stringify({ returnTo: "/notes?x=1#top" }),
      }),
    );
    assert.equal(started.status, 200, await started.clone().text());
    const transaction = started.headers.get("set-cookie")?.split(";")[0] ?? "";
    const { url: authorization } = (await started.json()) as { url: string };
    const redirected = await issuer.navigate(authorization);
    assert.equal(redirected.status, 302);
    const callbackUrl = new URL(redirected.location);
    assert.equal(`${callbackUrl.origin}${callbackUrl.pathname}`, `${origin}/auth/callback`);
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
    const principal = await verifier.verify(`Bearer ${token}`);
    // Tokens carry protocol scopes too; resource servers check for the scopes they define.
    assert.deepEqual(principal.scopes, ["openid", "offline_access", "notes:read", "notes:write"]);
    assert.deepEqual(principal.actor, { kind: "client", clientId: client.client_id });
    const other = createVerifier({ issuer: issuer.issuer, resource: `${origin}/mcp` });
    await assert.rejects(
      other.verifyToken(token),
      (error) => error instanceof AuthError && error.code === "unauthorized",
    );
    const session = await browser.session(
      new Request(`${origin}/auth/session`, { headers: { cookie } }),
    );
    assert.equal(session.status, 200);
    assert.equal(((await session.json()) as { subject: string }).subject, principal.subject);

    // API keys are verified online with their granted scopes and the key as actor.
    const created = await issuer.call("/api/createApiKey", {
      name: "Backup script",
      permissions: { [resource]: ["notes:read"] },
      expiresAt: null,
    });
    assert.equal(created.status, 201, await created.clone().text());
    const { key, keyId } = (await created.json()) as { key: string; keyId: string };
    const machine = await verifier.verify(`Bearer ${key}`);
    assert.equal(machine.subject, principal.subject);
    assert.deepEqual(machine.scopes, ["notes:read"]);
    assert.deepEqual(machine.actor, { kind: "key", keyId });
    await assert.rejects(
      other.verifyToken(key),
      (error) => error instanceof AuthError && error.code === "forbidden",
    );
    assert.equal((await issuer.call("/api/updateApiKey", { keyId, enabled: false })).status, 200);
    await assert.rejects(
      verifier.verifyToken(key),
      (error) => error instanceof AuthError && error.code === "unauthorized",
    );

    // Logout revokes the refresh token at the issuer and ends the local session.
    const logout = await browser.logout(
      new Request(`${origin}/auth/logout`, { method: "POST", headers: { origin, cookie } }),
    );
    assert.equal(logout.status, 204);
    await assert.rejects(
      browser.accessToken(new Request(`${origin}/api`, { headers: { cookie } })),
      (error) => error instanceof AuthError && error.code === "unauthorized",
    );
    assert.deepEqual(failures, []);
  } finally {
    await issuer.close();
  }
});
