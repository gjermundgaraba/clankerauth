import { mcpRequest } from "@gjermundgaraba/effect-actions/Testing";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, test } from "vite-plus/test";
import { webApplication as application } from "./web-application.ts";
import { createOwner, initialize, openAuth, type Service } from "../src/auth.ts";
import { mcpOAuthGrant } from "./mcp-oauth-helper.ts";

const baseURL = "http://localhost:3000";

const clientOrigin = "https://mcp-client.example.test";

let directory: string;

let service: Service;

let handle: ReturnType<typeof application>;

beforeEach(async () => {
  directory = mkdtempSync(join(tmpdir(), "clankerauth-mcp-cors-"));
  service = await openAuth({
    baseURL,
    secret: randomBytes(32).toString("hex"),
    database: join(directory, "auth.sqlite"),
    host: "127.0.0.1",
    port: 3000,
    mcpAllowedOrigins: [clientOrigin],
  });
  await initialize(service);
  handle = application(service);
});

afterEach(async () => {
  await handle.dispose();
  await service.close();
  rmSync(directory, { recursive: true, force: true });
});

const list = (headers: Record<string, string> = {}) =>
  handle(mcpRequest({ method: "tools/list", url: `${baseURL}/mcp`, headers }));

const preflight = (
  origin: string,
  method = "POST",
  headers = "authorization, content-type, mcp-protocol-version",
) =>
  handle(
    new Request(`${baseURL}/mcp`, {
      method: "OPTIONS",
      headers: {
        origin,
        "access-control-request-method": method,
        "access-control-request-headers": headers,
      },
    }),
  );

const headerNames = (response: Response, header: string) =>
  (response.headers.get(header) ?? "")
    .toLowerCase()
    .split(",")
    .map((value) => value.trim());

const expectCors = (response: Response, origin: string) => {
  expect(response.headers.get("access-control-allow-origin")).toBe(origin);
  expect(response.headers.has("access-control-allow-credentials")).toBe(false);
  expect(headerNames(response, "vary")).toContain("origin");
};

test("allowed browser origins can preflight MCP without credentials", async () => {
  const allowedHeaders = [
    "Authorization",
    "Content-Type",
    "Accept",
    "Mcp-Protocol-Version",
    "Mcp-Session-Id",
    "Mcp-Method",
    "Mcp-Name",
    "Last-Event-ID",
  ];

  for (const origin of [clientOrigin, baseURL]) {
    for (const method of ["GET", "POST", "DELETE"]) {
      const response = await preflight(origin, method, allowedHeaders.join(", "));
      expect(response.status).toBe(204);
      expectCors(response, origin);
      expect(headerNames(response, "access-control-allow-methods")).toContain(method.toLowerCase());
      expect(headerNames(response, "access-control-allow-headers")).toEqual(
        expect.arrayContaining(allowedHeaders.map((name) => name.toLowerCase())),
      );
    }
  }
});

test("MCP preflight rejects unlisted origins, methods, and headers", async () => {
  for (const origin of [
    "https://unlisted.example.test",
    "https://mcp-client.example.test.evil.test",
    "null",
  ]) {
    const response = await preflight(origin);
    expect(response.status).toBe(403);
    expect(response.headers.has("access-control-allow-origin")).toBe(false);
  }

  expect((await preflight(clientOrigin, "PATCH")).status).toBe(403);
  expect((await preflight(clientOrigin, "POST", "authorization, x-unlisted")).status).toBe(403);
});

test("browser authentication failures expose the challenge and MCP headers", async () => {
  for (const authorization of [undefined, "Bearer invalid"]) {
    const response = await list(
      authorization === undefined
        ? { origin: clientOrigin }
        : { origin: clientOrigin, authorization },
    );

    expect(response.status).toBe(401);
    expectCors(response, clientOrigin);
    expect(response.headers.get("www-authenticate")).toContain('scope="admin"');
    expect(headerNames(response, "access-control-expose-headers")).toEqual(
      expect.arrayContaining(["www-authenticate", "mcp-session-id", "mcp-protocol-version"]),
    );
  }
});

test("MCP rejects unlisted origins before authentication and accepts originless native requests", async () => {
  const foreign = await list({ origin: "https://unlisted.example.test" });
  expect(foreign.status).toBe(403);
  expect(foreign.headers.has("access-control-allow-origin")).toBe(false);
  const native = await list();
  expect(native.status).toBe(401);
  expect(native.headers.has("access-control-allow-origin")).toBe(false);
});

test("an allowed external browser uses bearer MCP while dashboard cookie CSRF stays separate", async () => {
  const credentials = { email: "owner@example.internal", password: "test-only password123" };
  await createOwner(service, credentials);

  const login = await handle(
    new Request(`${baseURL}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { origin: baseURL, "content-type": "application/json" },
      body: JSON.stringify(credentials),
    }),
  );

  expect(login.status).toBe(200);

  const cookie = login.headers
    .getSetCookie()
    .map((part) => part.split(";")[0])
    .join("; ");

  const { tokens } = await mcpOAuthGrant(handle, baseURL, cookie);

  const response = await list({
    origin: clientOrigin,
    authorization: `Bearer ${tokens.access_token}`,
  });

  expect(response.status, await response.clone().text()).toBe(200);
  expectCors(response, clientOrigin);
  expect((await list({ origin: clientOrigin, cookie })).status).toBe(401);

  const foreignToken = await list({
    origin: "https://unlisted.example.test",
    authorization: `Bearer ${tokens.access_token}`,
  });

  expect(foreignToken.status).toBe(403);
  expect(foreignToken.headers.has("access-control-allow-origin")).toBe(false);

  const dashboard = await handle(
    new Request(`${baseURL}/api/administration/listClients`, {
      method: "POST",
      headers: { cookie, origin: clientOrigin, "content-type": "application/json" },
      body: "{}",
    }),
  );

  expect(dashboard.status).toBe(403);
  expect(dashboard.headers.has("access-control-allow-origin")).toBe(false);

  const missingSession = await handle(
    new Request(`${baseURL}/mcp`, {
      method: "POST",
      headers: {
        origin: clientOrigin,
        authorization: `Bearer ${tokens.access_token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-protocol-version": "2025-11-25",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    }),
  );

  expect(missingSession.status).toBe(400);
  expectCors(missingSession, clientOrigin);
  expect(missingSession.headers.get("x-content-type-options")).toBe("nosniff");
});

test("discovery middleware cannot bypass public CORS or security headers", async () => {
  for (const method of ["GET", "HEAD", "OPTIONS"]) {
    const response = await handle(
      new Request(`${baseURL}/.well-known/oauth-protected-resource/mcp`, {
        method,
        headers: { origin: clientOrigin },
      }),
    );

    expect(response.status).toBe(method === "OPTIONS" ? 204 : 200);
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    await response.body?.cancel();
  }
});
