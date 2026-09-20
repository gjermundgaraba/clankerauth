/** The package against the real server: forward-auth tokens, verification, API keys, logout. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "vite-plus/test";
import { nodeHandler } from "../src/app.ts";
import { initialize, openAuth } from "../src/auth.ts";
import { forwardClientId } from "../src/forward-auth.ts";
import { testSettings } from "./settings.ts";
import { createNodeServer } from "../src/node-http.ts";
import { Effect, Exit, Schema, Scope } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { Unauthorized, Forbidden } from "@gjermundgaraba/clankerauth-sdk";
import { Resource } from "@gjermundgaraba/clankerauth-sdk/effect-actions";

const owner = { email: "owner@example.internal", password: randomBytes(24).toString("base64url") };

const ApiKeyCreated = Schema.Struct({ key: Schema.String, keyId: Schema.String });

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

  const call = async (
    path: string,
    body?: typeof Schema.Json.Type,
    headers: Record<string, string> = {},
  ) => {
    const request = new Headers({ origin: url, cookie: cookieHeader(), ...headers });

    if (body) request.set("content-type", "application/json");

    const response = await fetch(new URL(path, url), {
      method: body ? "POST" : "GET",
      redirect: "manual",
      headers: request,
      body: body ? JSON.stringify(body) : undefined,
    });

    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      cookies.set(pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1));
    }

    return response;
  };

  /** The proxy's subrequest for a browser request to `original` on an app behind it. */
  const forward = (resource: string, original: URL) =>
    call(`/forward-auth?resource=${encodeURIComponent(resource)}`, undefined, {
      "x-forwarded-proto": original.protocol.slice(0, -1),
      "x-forwarded-host": original.host,
      "x-forwarded-uri": `${original.pathname}${original.search}`,
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

  return { url, issuer: `${url}/api/auth`, call, forward, close };
};

test("forward-auth tokens and API keys verify with the SDK against the real issuer, until logout", async () => {
  const issuer = await startServer();
  // Without a cookie domain, forward auth covers apps on the issuer's own host.
  const app = new URL("/notes?x=1", issuer.url.replace(/:\d+$/, ":7337"));
  const resource = `${app.origin}/api`;

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

    const { verifier } = await Effect.runPromise(
      Resource.make({
        issuer: issuer.issuer,
        resource,
        requiredScopes: ["notes:read"],
        scopes: ["notes:read", "notes:write"],
      }).pipe(Effect.provide(FetchHttpClient.layer)),
    );

    // After login the owner continues to the app, which sets the forward cookie; the proxy's
    // subrequest then yields a token the verifier accepts for this resource only.
    const proceed = await issuer.call(`/forward-auth/continue?rd=${encodeURIComponent(app.href)}`);
    assert.equal(proceed.status, 302, await proceed.text());
    assert.equal(proceed.headers.get("location"), app.href);
    const forwarded = await issuer.forward(resource, app);
    assert.equal(forwarded.status, 204, await forwarded.text());
    const authorization = forwarded.headers.get("authorization") ?? "";
    const principal = await Effect.runPromise(verifier.verify(authorization));
    assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
    assert.deepEqual(principal.actor, { kind: "client", clientId: forwardClientId });

    const { verifier: other } = await Effect.runPromise(
      Resource.make({ issuer: issuer.issuer, resource: `${app.origin}/mcp`, scopes: [] }).pipe(
        Effect.provide(FetchHttpClient.layer),
      ),
    );

    const token = authorization.slice("Bearer ".length);
    await assert.rejects(
      Effect.runPromise(other.verifyToken(token)),
      (error) => error instanceof Unauthorized,
    );

    // API keys are verified online with their granted scopes and the key as actor.
    const created = await issuer.call("/api/administration/createApiKey", {
      name: "Backup script",
      permissions: { [resource]: ["notes:read"] },
      expiresAt: null,
    });

    assert.equal(created.status, 201, await created.clone().text());
    const { key, keyId } = Schema.decodeUnknownSync(ApiKeyCreated)(await created.json());
    const machine = await Effect.runPromise(verifier.verify(`Bearer ${key}`));
    assert.equal(machine.subject, principal.subject);
    assert.deepEqual(machine.scopes, ["notes:read"]);
    assert.deepEqual(machine.actor, { kind: "key", keyId });
    await assert.rejects(
      Effect.runPromise(other.verifyToken(key)),
      (error) => error instanceof Forbidden,
    );
    assert.equal(
      (await issuer.call("/api/administration/updateApiKey", { keyId, enabled: false })).status,
      200,
    );
    await assert.rejects(
      Effect.runPromise(verifier.verifyToken(key)),
      (error) => error instanceof Unauthorized,
    );

    // Logout ends the issuer session; the next browser request is sent through the issuer,
    // which finds no session and asks for login.
    const logout = await issuer.call(`/forward-auth/logout?rd=${encodeURIComponent(app.href)}`);
    assert.equal(logout.status, 302);
    assert.equal(logout.headers.get("location"), app.href);
    const again = await issuer.forward(resource, app);
    assert.equal(again.status, 302);
    const next = new URL(again.headers.get("location") ?? "");
    assert.equal(`${next.origin}${next.pathname}`, `${issuer.url}/forward-auth/continue`);
    assert.equal(next.searchParams.get("rd"), app.href);
    const login = await issuer.call(`${next.pathname}${next.search}`);
    assert.equal(login.status, 302);
    const target = new URL(login.headers.get("location") ?? "");
    assert.equal(`${target.origin}${target.pathname}`, `${issuer.url}/login`);
    assert.equal(target.searchParams.get("rd"), app.href);
  } finally {
    await issuer.close();
  }
});
