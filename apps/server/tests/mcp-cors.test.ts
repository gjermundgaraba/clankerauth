import { it } from "@effect/vitest";
import { Effect } from "effect";
import { expect } from "vite-plus/test";

import { OwnerAccount } from "../src/owner/owner.ts";
import { mcpOAuthGrant } from "./mcp-oauth-helper.ts";
import type { TestHandler } from "./mcp-oauth-helper.ts";
import { webMcpRequest } from "./mcp.ts";
import { signIn, testWebApplication, WebApplication } from "./test-issuer.ts";

const baseURL = "http://localhost:3000";

const clientOrigin = "https://mcp-client.example.test";

const corsIssuer = () =>
  testWebApplication({ baseURL, mcpAllowedOrigins: [clientOrigin] });

const send = (handle: TestHandler, request: Request) =>
  Effect.promise(async () => await handle(request));

const list = (handle: TestHandler, headers: Record<string, string> = {}) =>
  send(
    handle,
    webMcpRequest({ method: "tools/list", url: `${baseURL}/mcp`, headers })
  );

const preflight = (
  handle: TestHandler,
  origin: string,
  method = "POST",
  headers = "authorization, content-type, mcp-protocol-version"
) =>
  send(
    handle,
    new Request(`${baseURL}/mcp`, {
      method: "OPTIONS",
      headers: {
        origin,
        "access-control-request-method": method,
        "access-control-request-headers": headers,
      },
    })
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

it.live("allowed browser origins can preflight MCP without credentials", () =>
  Effect.gen(function* () {
    const handle = yield* WebApplication;

    const allowedHeaders = [
      "Authorization",
      "Content-Type",
      "Accept",
      "Mcp-Protocol-Version",
      "Mcp-Method",
      "Mcp-Name",
    ];

    for (const origin of [clientOrigin, baseURL]) {
      const response = yield* preflight(
        handle,
        origin,
        "POST",
        allowedHeaders.join(", ")
      );

      expect(response.status).toBe(204);
      expectCors(response, origin);
      expect(
        headerNames(response, "access-control-allow-methods")
      ).toStrictEqual(["post"]);
      expect(
        headerNames(response, "access-control-allow-headers")
      ).toStrictEqual(
        expect.arrayContaining(allowedHeaders.map((name) => name.toLowerCase()))
      );
    }
  }).pipe(Effect.provide(corsIssuer()))
);

it.live("MCP preflight rejects unlisted origins, methods, and headers", () =>
  Effect.gen(function* () {
    const handle = yield* WebApplication;

    for (const origin of [
      "https://unlisted.example.test",
      "https://mcp-client.example.test.evil.test",
      "null",
    ]) {
      const response = yield* preflight(handle, origin);
      expect(response.status).toBe(403);
      expect(response.headers.has("access-control-allow-origin")).toBe(false);
    }

    // why: stateless 2026-07-28 MCP has no GET stream, session deletion, or session headers
    for (const method of ["GET", "DELETE", "PATCH"]) {
      expect((yield* preflight(handle, clientOrigin, method)).status).toBe(403);
    }

    for (const header of ["x-unlisted", "mcp-session-id", "last-event-id"]) {
      expect(
        (yield* preflight(
          handle,
          clientOrigin,
          "POST",
          `authorization, ${header}`
        )).status
      ).toBe(403);
    }
  }).pipe(Effect.provide(corsIssuer()))
);

it.live(
  "browser authentication failures expose the challenge and MCP headers",
  () =>
    Effect.gen(function* () {
      const handle = yield* WebApplication;

      for (const authorization of [undefined, "Bearer invalid"]) {
        const response = yield* list(
          handle,
          authorization === undefined
            ? { origin: clientOrigin }
            : { origin: clientOrigin, authorization }
        );

        expect(response.status).toBe(401);
        expectCors(response, clientOrigin);
        expect(
          headerNames(response, "access-control-expose-headers")
        ).toStrictEqual(["www-authenticate", "mcp-protocol-version"]);
      }
    }).pipe(Effect.provide(corsIssuer()))
);

it.live(
  "MCP rejects unlisted origins before authentication and accepts originless native requests",
  () =>
    Effect.gen(function* () {
      const handle = yield* WebApplication;

      const foreign = yield* list(handle, {
        origin: "https://unlisted.example.test",
      });

      expect(foreign.status).toBe(403);
      expect(foreign.headers.has("access-control-allow-origin")).toBe(false);
      const native = yield* list(handle);
      expect(native.status).toBe(401);
      expect(native.headers.has("access-control-allow-origin")).toBe(false);
    }).pipe(Effect.provide(corsIssuer()))
);

it.live(
  "an allowed external browser uses bearer MCP while the dashboard API exposes no CORS grant",
  () =>
    Effect.gen(function* () {
      const handle = yield* WebApplication;

      const credentials = {
        email: "owner@example.internal",
        password: "test-only password123",
      };

      yield* (yield* OwnerAccount).create(credentials);

      const cookie = yield* signIn(handle, baseURL, credentials);

      const { tokens } = yield* Effect.promise(
        async () => await mcpOAuthGrant(handle, baseURL, cookie)
      );

      const response = yield* list(handle, {
        origin: clientOrigin,
        authorization: `Bearer ${tokens.access_token}`,
      });

      expect(
        response.status,
        yield* Effect.promise(async () => await response.clone().text())
      ).toBe(200);
      expectCors(response, clientOrigin);
      expect(
        (yield* list(handle, { origin: clientOrigin, cookie })).status
      ).toBe(401);

      const foreignToken = yield* list(handle, {
        origin: "https://unlisted.example.test",
        authorization: `Bearer ${tokens.access_token}`,
      });

      expect(foreignToken.status).toBe(403);
      expect(foreignToken.headers.has("access-control-allow-origin")).toBe(
        false
      );

      const dashboard = yield* send(
        handle,
        new Request(`${baseURL}/api/listClients`, {
          method: "POST",
          headers: {
            cookie,
            origin: clientOrigin,
            "content-type": "application/json",
          },
          body: "{}",
        })
      );

      expect(dashboard.status).toBe(200);
      expect(dashboard.headers.has("access-control-allow-origin")).toBe(false);
    }).pipe(Effect.provide(corsIssuer()))
);

it.live(
  "discovery middleware cannot bypass public CORS or security headers",
  () =>
    Effect.gen(function* () {
      const handle = yield* WebApplication;

      for (const method of ["GET", "HEAD", "OPTIONS"]) {
        const response = yield* send(
          handle,
          new Request(`${baseURL}/.well-known/oauth-protected-resource`, {
            method,
            headers: { origin: clientOrigin },
          })
        );

        expect(response.status).toBe(method === "OPTIONS" ? 204 : 200);
        expect(response.headers.get("access-control-allow-origin")).toBe("*");
        expect(response.headers.get("cache-control")).toBe(
          method === "GET" ? "public, max-age=300" : "no-store"
        );
        expect(response.headers.get("x-content-type-options")).toBe("nosniff");
        yield* Effect.promise(async () => {
          await response.body?.cancel();
        });
      }
    }).pipe(Effect.provide(corsIssuer()))
);
