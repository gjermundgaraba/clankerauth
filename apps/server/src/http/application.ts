import nodePath from "node:path";
import { fileURLToPath } from "node:url";

import { documentPaths } from "@clankerauth/web/document-paths";
import { NodeHttpServer } from "@effect/platform-node";
import type { Schema } from "effect";
import { Effect, Layer } from "effect";
import {
  HttpPlatform,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/http";

import { forwardAuthRoutes } from "../forward-auth/forward-auth.ts";
import { provider, respond } from "../issuer/errors.ts";
import { Issuer } from "../issuer/issuer.ts";
import { Settings } from "../issuer/settings.ts";
import { requestPolicy } from "../platform/node-http.ts";
import { Database } from "../platform/sqlite.ts";
import { exactlyOneResource, ResourceCatalog } from "../resources/catalog.ts";
import { actionRoutes } from "./actions.ts";

const publicPaths = new Set([
  "/sign-in/email",
  "/sign-out",
  "/get-session",
  "/change-password",
  "/jwks",
  "/oauth2/register",
  "/oauth2/authorize",
  "/oauth2/token",
  "/oauth2/consent",
  "/oauth2/continue",
  "/oauth2/public-client",
  "/oauth2/introspect",
  "/oauth2/revoke",
  "/.well-known/oauth-authorization-server",
]);

const corsPaths = new Set([
  "/.well-known/oauth-protected-resource",
  "/jwks",
  "/oauth2/register",
  "/oauth2/token",
  "/oauth2/revoke",
  "/oauth2/introspect",
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-authorization-server/api/auth",
]);

const cacheablePaths = new Set([
  "/jwks",
  "/.well-known/oauth-protected-resource",
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-authorization-server/api/auth",
]);

const spaRoutes = new Set(documentPaths);

const assetPath = /^\/assets\/[a-zA-Z0-9_.-]+\.(?:js|css|woff2)$/u;

const staticFile = (path: string) => {
  if (spaRoutes.has(path)) {
    return "index.html";
  }

  return assetPath.test(path) ? path.slice(1) : undefined;
};

const contentType = (file: string) => {
  if (file.endsWith(".js")) {
    return "text/javascript";
  }

  if (file.endsWith(".css")) {
    return "text/css";
  }

  return file.endsWith(".woff2") ? "font/woff2" : "text/html; charset=utf-8";
};

const cachePolicy = (pathname: string, path: string) => {
  if (pathname.startsWith("/assets/")) {
    return "public, max-age=31536000, immutable";
  }

  return cacheablePaths.has(path) ? "public, max-age=300" : "no-store";
};

const json = (body: Schema.Json, status = 200) =>
  HttpServerResponse.jsonUnsafe(body, { status });

const notFound = json({ error: "Not found" }, 404);

const mcpRequestHeaders = [
  "Authorization",
  "Content-Type",
  "Accept",
  "Mcp-Protocol-Version",
  "Mcp-Method",
  "Mcp-Name",
];

const mcpRequestHeaderNames = new Set(
  mcpRequestHeaders.map((header) => header.toLowerCase())
);

export const application = (
  staticRoot = fileURLToPath(
    new URL("dist/", import.meta.resolve("@clankerauth/web/package.json"))
  )
) =>
  Layer.unwrap(
    Effect.gen(function* () {
      const settings = yield* Settings;
      const { auth } = yield* Issuer;
      const { sql } = yield* Database;
      const catalog = yield* ResourceCatalog;

      const mcpAllowedOrigins = [
        ...new Set([settings.baseURL, ...settings.mcpAllowedOrigins]),
      ];

      const bridge = Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const url = new URL(request.url, settings.baseURL);
        const path = url.pathname.replace(/^\/api\/auth/u, "");

        if (
          !publicPaths.has(path) &&
          path !== "/.well-known/oauth-authorization-server/api/auth"
        ) {
          return notFound;
        }

        if (path === "/oauth2/authorize") {
          const resources =
            request.method === "GET"
              ? url.searchParams.getAll("resource")
              : new URLSearchParams(yield* request.text).getAll("resource");

          if (
            resources.length !== 1 ||
            !(yield* catalog.get(resources[0] ?? ""))
          ) {
            return json(
              {
                error: "invalid_target",
                error_description: exactlyOneResource,
              },
              400
            );
          }
        }

        const body =
          request.method === "GET" || request.method === "HEAD"
            ? null
            : yield* request.arrayBuffer;

        const response = yield* provider(
          async () =>
            await auth.handler(
              new Request(url, {
                method: request.method,
                headers: request.headers,
                body,
              })
            )
        );

        return HttpServerResponse.fromWeb(response);
      }).pipe(Effect.catch(respond));

      const staticRoutes = HttpRouter.use((router) =>
        Effect.gen(function* () {
          const platform = yield* HttpPlatform.HttpPlatform;
          yield* router.add(
            "*",
            "/*",
            Effect.gen(function* () {
              const request = yield* HttpServerRequest.HttpServerRequest;

              if (request.method !== "GET" && request.method !== "HEAD") {
                return notFound;
              }

              const path = new URL(request.url, settings.baseURL).pathname;

              const file = staticFile(path);

              if (file === undefined) {
                return notFound;
              }

              return yield* platform
                .fileResponse(nodePath.resolve(staticRoot, file), {
                  contentType: contentType(file),
                })
                .pipe(Effect.orElseSucceed(() => notFound));
            })
          );
        })
      );

      const policy = HttpRouter.middleware(
        (handler) =>
          requestPolicy({
            baseURL: settings.baseURL,
            trustProxy: settings.trustProxy,
          })(
            Effect.gen(function* () {
              const request = yield* HttpServerRequest.HttpServerRequest;
              const { pathname } = new URL(request.url, settings.baseURL);
              const path = pathname.replace(/^\/api\/auth/u, "");
              const isMcp = pathname === "/mcp";
              const { origin } = request.headers;

              const mcpOriginAllowed =
                origin !== undefined && mcpAllowedOrigins.includes(origin);

              const publicCors = corsPaths.has(path);
              let response: HttpServerResponse.HttpServerResponse;

              if (isMcp && origin !== undefined && !mcpOriginAllowed) {
                response = json({ error: "Invalid origin" }, 403);
              } else if (isMcp && request.method === "OPTIONS") {
                const method = request.headers["access-control-request-method"];

                const headers = (
                  request.headers["access-control-request-headers"] ?? ""
                )
                  .split(",")
                  .map((header) => header.trim().toLowerCase())
                  .filter(Boolean);

                response =
                  mcpOriginAllowed &&
                  method === "POST" &&
                  headers.every((header) => mcpRequestHeaderNames.has(header))
                    ? HttpServerResponse.empty({ status: 204 })
                    : json({ error: "MCP preflight rejected" }, 403);
              } else if (publicCors && request.method === "OPTIONS") {
                response = HttpServerResponse.empty({ status: 204 });
              } else {
                response = yield* handler;
              }

              if (publicCors) {
                response = response.pipe(
                  HttpServerResponse.setHeaders({
                    "access-control-allow-origin": "*",
                    "access-control-allow-methods": "GET, POST, OPTIONS",
                    "access-control-allow-headers":
                      "Authorization, Content-Type, DPoP",
                    "access-control-expose-headers":
                      "WWW-Authenticate, DPoP-Nonce",
                  }),
                  HttpServerResponse.removeHeader(
                    "access-control-allow-credentials"
                  )
                );
              }

              if (isMcp) {
                const { vary } = response.headers;

                response = response.pipe(
                  HttpServerResponse.setHeader(
                    "vary",
                    vary === undefined || vary === ""
                      ? "Origin"
                      : `${vary}, Origin`
                  ),
                  HttpServerResponse.removeHeader(
                    "access-control-allow-credentials"
                  )
                );

                if (mcpOriginAllowed && origin !== undefined) {
                  response = response.pipe(
                    HttpServerResponse.setHeaders({
                      "access-control-allow-origin": origin,
                      "access-control-expose-headers":
                        "WWW-Authenticate, Mcp-Protocol-Version",
                    })
                  );

                  if (
                    request.method === "OPTIONS" &&
                    response.status >= 200 &&
                    response.status < 300
                  ) {
                    response = response.pipe(
                      HttpServerResponse.setHeaders({
                        "access-control-allow-methods": "POST",
                        "access-control-allow-headers":
                          mcpRequestHeaders.join(", "),
                      })
                    );
                  }
                }
              }

              const cacheable =
                request.method === "GET" && response.status === 200;

              const cacheControl = cacheable
                ? cachePolicy(pathname, path)
                : "no-store";

              response = response.pipe(
                HttpServerResponse.setHeaders({
                  "cache-control": cacheControl,
                  "referrer-policy": "no-referrer",
                  "x-content-type-options": "nosniff",
                  "x-frame-options": "DENY",
                  "content-security-policy":
                    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                })
              );

              if (settings.baseURL.startsWith("https:")) {
                response = response.pipe(
                  HttpServerResponse.setHeader(
                    "strict-transport-security",
                    "max-age=31536000"
                  )
                );
              }

              return response;
            })
          ),
        { global: true }
      );

      const uninterruptible = HttpRouter.middleware((handler) =>
        Effect.uninterruptible(handler)
      );

      return Layer.mergeAll(
        actionRoutes(mcpAllowedOrigins),
        settings.cookieDomain === undefined
          ? Layer.empty
          : forwardAuthRoutes(settings.cookieDomain),
        HttpRouter.add(
          "GET",
          "/healthz",
          sql`SELECT 1`.pipe(
            Effect.as(json({ status: "ok" })),
            Effect.catch(respond)
          )
        ),
        HttpRouter.add("*", "/api/auth/*", bridge),
        HttpRouter.add("*", "/.well-known/*", bridge),
        staticRoutes
      ).pipe(
        Layer.provide(uninterruptible.layer),
        Layer.provide(policy),
        Layer.provide(NodeHttpServer.layerHttpServices)
      );
    })
  );

export const nodeHandler = Effect.fn("Http.nodeHandler")(function* (
  staticRoot?: string
) {
  const handler = yield* HttpRouter.toHttpEffect(application(staticRoot));

  return yield* NodeHttpServer.makeHandler(handler, {
    scope: yield* Effect.scope,
  });
});
