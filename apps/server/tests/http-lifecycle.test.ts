import { afterEach, beforeEach, expect, test, vi } from "vite-plus/test";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Exit, Schema, Scope } from "effect";
import { nodeHandler } from "../src/app.ts";
import { initialize, openAuth, type Service } from "../src/auth.ts";
import { createNodeServer } from "../src/node-http.ts";

let directory: string;

let service: Service;

let scope: Scope.Closeable;

let server: Server;

let url: string;

let closing: Promise<void> | undefined;

beforeEach(async () => {
  directory = mkdtempSync(join(tmpdir(), "clankerauth-http-lifecycle-"));
  service = await openAuth({
    baseURL: "https://issuer.example",
    secret: "test-only-secret-with-at-least-32-characters",
    database: join(directory, "auth.sqlite"),
    host: "127.0.0.1",
    port: 3000,
  });
  await initialize(service);
  scope = Scope.makeUnsafe();

  const listener = await Effect.runPromise(
    nodeHandler(service).pipe(Effect.provideService(Scope.Scope, scope)),
  );

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
  await (closing ?? service.close());
  vi.restoreAllMocks();
  rmSync(directory, { recursive: true, force: true });
});

test("provider requests receive disconnect cancellation while shutdown waits for their actual settlement", async () => {
  const entered = Promise.withResolvers<Request>();
  const release = Promise.withResolvers<void>();
  const cancel = vi.fn();
  const destroy = vi.spyOn(service.database, "destroy");
  vi.spyOn(service.auth, "handler").mockImplementation(async (request) => {
    entered.resolve(request);
    await release.promise;
    // Work still owned by the provider must not encounter a closed database.
    await Effect.runPromise(service.sql`SELECT 1`);

    return new Response(new ReadableStream({ cancel }));
  });
  const controller = new AbortController();
  const response = fetch(`${url}/api/auth/jwks`, { signal: controller.signal });
  const rejected = expect(response).rejects.toThrow();

  try {
    const request = await entered.promise;
    expect(request.url).toBe("https://issuer.example/api/auth/jwks");
    const aborted = once(request.signal, "abort");
    controller.abort();
    await rejected;
    await aborted;
    closing = Effect.runPromise(Scope.close(scope, Exit.void)).then(() => service.close());
    expect(destroy).not.toHaveBeenCalled();
    release.resolve();
    await closing;
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(destroy).toHaveBeenCalledTimes(1);
  } finally {
    release.resolve();
  }
});

test("disconnect does not abandon an uncancellable SDK call in an action route", async () => {
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const destroy = vi.spyOn(service.database, "destroy");
  vi.spyOn(service.auth.api, "getSession").mockImplementation(async () => {
    entered.resolve();
    await release.promise;
    await Effect.runPromise(service.sql`SELECT 1`);

    return null;
  });
  const controller = new AbortController();

  const response = fetch(`${url}/api/listClients`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://issuer.example" },
    body: "{}",
    signal: controller.signal,
  });

  const rejected = expect(response).rejects.toThrow();

  try {
    await entered.promise;
    controller.abort();
    await rejected;
    closing = Effect.runPromise(Scope.close(scope, Exit.void)).then(() => service.close());
    expect(destroy).not.toHaveBeenCalled();
    release.resolve();
    await closing;
    expect(destroy).toHaveBeenCalledTimes(1);
  } finally {
    release.resolve();
  }
});

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
  ["malformed JSON", "{", 400, false],
  ["missing resource", "{}", 400, false],
  ["non-string resource", '{"resource":42}', 400, false],
  ["unknown resource", '{"resource":"https://unknown.example"}', 400, false],
  ["known resource", '{"resource":"https://issuer.example/mcp"}', 200, true],
  [
    "unrelated overflowing number",
    '{"resource":"https://issuer.example/mcp","extra":1e400}',
    200,
    true,
  ],
])("OAuth resource admission: %s", async (_name, body, status, admitted) => {
  const handler = vi.spyOn(service.auth, "handler").mockResolvedValue(new Response("provider"));

  const response = await fetch(`${url}/api/auth/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });

  expect(response.status).toBe(status);
  await response.text();
  expect(handler).toHaveBeenCalledTimes(admitted ? 1 : 0);
});
