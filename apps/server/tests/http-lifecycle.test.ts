import { afterEach, beforeEach, expect, test, vi } from "vite-plus/test";
import { once } from "node:events";
import type { Server } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { Effect, Exit, Schema, Scope } from "effect";
import { generateKeyPair, SignJWT } from "jose";
import { mcpRequest } from "@gjermundgaraba/effect-actions/Testing";
import { nodeHandler } from "../src/app.ts";
import { openIssuer, type Issuer } from "./issuer.ts";
import { createNodeServer } from "../src/node-http.ts";

let issuer: Issuer;

let service: Issuer["service"];

let scope: Scope.Closeable;

let server: Server;

let url: string;

let closing: Promise<void> | undefined;

beforeEach(async () => {
  issuer = await openIssuer({ baseURL: "https://issuer.example" });
  service = issuer.service;
  scope = Scope.makeUnsafe();

  const listener = await issuer.run(nodeHandler().pipe(Effect.provideService(Scope.Scope, scope)));

  server = createNodeServer(listener);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");

  const { port } = Schema.decodeUnknownSync(Schema.Struct({ port: Schema.Number }))(
    server.address(),
  );

  url = `http://127.0.0.1:${port}`;
  closing = undefined;
});

afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await Effect.runPromise(Scope.close(scope, Exit.void));
  await closing;
  vi.restoreAllMocks();
  await issuer.close();
});

test("shutdown waits for a provider request to settle after its client disconnects", async () => {
  const entered = Promise.withResolvers<Request>();
  const release = Promise.withResolvers<void>();
  const destroy = vi.spyOn(service.database, "destroy");
  vi.spyOn(service.auth, "handler").mockImplementation(async (request) => {
    entered.resolve(request);
    await release.promise;
    // Work still owned by the provider must not encounter a closed database.
    await Effect.runPromise(service.sql`SELECT 1`);

    return Response.json({ keys: [] });
  });
  const controller = new AbortController();
  const response = fetch(`${url}/api/auth/jwks`, { signal: controller.signal });
  const rejected = expect(response).rejects.toThrow();

  try {
    const request = await entered.promise;
    expect(request.url).toBe("https://issuer.example/api/auth/jwks");
    controller.abort();
    await rejected;
    closing = Effect.runPromise(Scope.close(scope, Exit.void)).then(() => issuer.stop());
    expect(destroy).not.toHaveBeenCalled();
    release.resolve();
    await closing;
    expect(destroy).toHaveBeenCalledTimes(1);
  } finally {
    release.resolve();
  }
});

test("disconnect does not abandon an uncancellable SDK call in an action route", async () => {
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const destroy = vi.spyOn(service.database, "destroy");
  const context = await service.auth.$context;
  const hash = context.password.hash;
  // Sign-up hashes inside the provider's transaction, which holds the connection.
  vi.spyOn(context.password, "hash").mockImplementation(async (password) => {
    entered.resolve();
    await release.promise;

    return hash(password);
  });
  const controller = new AbortController();

  const response = fetch(`${url}/api/issuer/setupOwner`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://issuer.example" },
    body: JSON.stringify({ email: "owner@example.com", password: "test-password-long-enough" }),
    signal: controller.signal,
  });

  const rejected = expect(response).rejects.toThrow();

  try {
    await entered.promise;
    controller.abort();
    await rejected;
    closing = Effect.runPromise(Scope.close(scope, Exit.void)).then(() => issuer.stop());
    expect(destroy).not.toHaveBeenCalled();
    release.resolve();
    await closing;
    expect(destroy).toHaveBeenCalledTimes(1);
    // The disconnected request still committed the account before the database closed.
    const stored = new DatabaseSync(issuer.settings.database);
    expect(stored.prepare("SELECT count(*) AS n FROM user").get()).toEqual({ n: 1 });
    stored.close();
  } finally {
    release.resolve();
  }
});

test("an in-process JWKS read is awaited by its request, so shutdown waits for it", async () => {
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const destroy = vi.spyOn(service.database, "destroy");
  const handler = service.auth.handler;
  let stalledCallFailed: unknown;

  vi.spyOn(service.auth, "handler").mockImplementation(async (request) => {
    if (new URL(request.url).pathname.endsWith("/jwks")) {
      entered.resolve();
      await release.promise;
      // Work still owned by the provider must not encounter a closed database.
      await Effect.runPromise(service.sql`SELECT 1`).catch((cause: unknown) => {
        stalledCallFailed = cause;
      });
    }

    return handler(request);
  });

  const { privateKey } = await generateKeyPair("EdDSA");

  const token = await new SignJWT({ scope: "admin", client_id: "stalled", azp: "stalled" })
    .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid: "unknown" })
    .setIssuer("https://issuer.example/api/auth")
    .setAudience("https://issuer.example/mcp")
    .setSubject("owner")
    .setIssuedAt()
    .setExpirationTime("5m")
    .setJti("stalled")
    .sign(privateKey);

  let answered = false;

  const response = fetch(
    mcpRequest({
      method: "tools/list",
      url: `${url}/mcp`,
      headers: { authorization: `Bearer ${token}` },
    }),
  ).then((answer) => {
    answered = true;

    return answer;
  });

  try {
    await entered.promise;
    closing = Effect.runPromise(Scope.close(scope, Exit.void)).then(() => issuer.stop());
    // Past the deadline a Resource would apply: the raw verifier has none, so the request
    // fiber is still waiting on the provider, and shutdown is still waiting on the fiber.
    await new Promise((resolve) => setTimeout(resolve, 5500));
    expect(answered).toBe(false);
    expect(destroy).not.toHaveBeenCalled();
    release.resolve();
    // Shutdown interrupts the request once its provider work is done, so the client
    // sees the interruption, not a verdict; the provider's query still reached SQLite.
    await response;
    await closing;
    expect(destroy).toHaveBeenCalledTimes(1);
    expect(stalledCallFailed).toBeUndefined();
  } finally {
    release.resolve();
  }
}, 15000);

test.each(["GET", "HEAD"])("%s reaches the provider without a body", async (method) => {
  const handler = vi.spyOn(service.auth, "handler").mockImplementation(async (request) => {
    expect(request.method).toBe(method);
    expect(request.body).toBeNull();

    return new Response("provider response");
  });

  const response = await fetch(`${url}/api/auth/jwks`, { method });
  expect(response.status).toBe(200);
  expect(await response.text()).toBe(method === "HEAD" ? "" : "provider response");
  expect(handler).toHaveBeenCalledTimes(1);
});

test("POST preserves provider body bytes and content type", async () => {
  const body = ' { "email": "owner@example.internal" }\n';

  const handler = vi.spyOn(service.auth, "handler").mockImplementation(async (request) => {
    expect(request.method).toBe("POST");
    expect(request.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(new Uint8Array(await request.arrayBuffer())).toEqual(new TextEncoder().encode(body));

    return new Response("ok");
  });

  const response = await fetch(`${url}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { "content-type": "application/json; charset=utf-8" },
    body,
  });

  expect(response.status).toBe(200);
  expect(await response.text()).toBe("ok");
  expect(handler).toHaveBeenCalledTimes(1);
});

test.each([
  ["missing resource", "", 400, false],
  ["unknown resource", "?resource=https://unknown.example", 400, false],
  [
    "several resources",
    "?resource=https://issuer.example/mcp&resource=https://issuer.example/mcp",
    400,
    false,
  ],
  ["known resource", "?resource=https://issuer.example/mcp", 200, true],
])("authorization resource admission: %s", async (_name, query, status, admitted) => {
  const handler = vi.spyOn(service.auth, "handler").mockResolvedValue(new Response("provider"));
  const response = await fetch(`${url}/api/auth/oauth2/authorize${query}`);
  expect(response.status).toBe(status);
  await response.text();
  expect(handler).toHaveBeenCalledTimes(admitted ? 1 : 0);
});

test("bodies above 64 KiB are disconnected before reaching the provider", async () => {
  const handler = vi.spyOn(service.auth, "handler").mockResolvedValue(new Response("provider"));

  await expect(
    fetch(`${url}/api/auth/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `grant_type=${"x".repeat(65536)}`,
    }),
  ).rejects.toThrow();
  expect(handler).not.toHaveBeenCalled();
});

test("token requests reach the provider without resource pre-checks", async () => {
  const handler = vi.spyOn(service.auth, "handler").mockResolvedValue(new Response("provider"));

  const response = await fetch(`${url}/api/auth/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=refresh_token",
  });

  expect(response.status).toBe(200);
  await response.text();
  expect(handler).toHaveBeenCalledTimes(1);
});
