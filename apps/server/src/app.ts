import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Effect, Layer, Schema } from "effect";
import { NodeHttpServer } from "@effect/platform-node";
import {
  HttpPlatform,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";
import { provider, respond } from "./api-errors.ts";
import { Auth } from "./auth.ts";
import { actionRoutes } from "./action-api.ts";
import { forwardAuthRoutes } from "./forward-auth.ts";
import { requestPolicy } from "./node-http.ts";

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
  "/.well-known/oauth-protected-resource/mcp",
  "/jwks",
  "/oauth2/register",
  "/oauth2/token",
  "/oauth2/revoke",
  "/oauth2/introspect",
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-authorization-server/api/auth",
]);

/** Public, unauthenticated documents resource servers and clients may cache briefly. */
const cacheablePaths = new Set([
  "/jwks",
  "/.well-known/oauth-protected-resource/mcp",
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-authorization-server/api/auth",
]);

const spaRoutes = new Set(["/", "/login", "/consent", "/setup"]);

const assetPath = /^\/assets\/[a-zA-Z0-9_.-]+\.(js|css)$/;

const json = (body: typeof Schema.Json.Type, status = 200) =>
  HttpServerResponse.jsonUnsafe(body, { status });

const notFound = json({ error: "Not found" }, 404);

/** Stateless 2026-07-28 MCP is POST only, with no session or stream-resumption headers. */
const mcpRequestHeaders = [
  "Authorization",
  "Content-Type",
  "Accept",
  "Mcp-Protocol-Version",
  "Mcp-Method",
  "Mcp-Name",
];

const mcpRequestHeaderNames = new Set(mcpRequestHeaders.map((header) => header.toLowerCase()));

/** All routes remain native Effect HTTP, except the Better Auth adapter. */
export const application = (
  staticRoot = fileURLToPath(
    new URL("dist/", import.meta.resolve("@clankerauth/web/package.json")),
  ),
) =>
  Layer.unwrap(
    Effect.map(Auth, (service) => {
      const { auth, settings } = service;
      const mcpAllowedOrigins = [...new Set([settings.baseURL, ...settings.mcpAllowedOrigins])];

      const bridge = Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const url = new URL(request.url, settings.baseURL);
        const path = url.pathname.replace(/^\/api\/auth/, "");

        if (!publicPaths.has(path) && path !== "/.well-known/oauth-authorization-server/api/auth")
          return notFound;

        // Application policy: every authorization targets exactly one configured resource.
        // The provider validates the resource on token requests itself.
        if (path === "/oauth2/authorize") {
          const resources =
            request.method === "GET"
              ? url.searchParams.getAll("resource")
              : new URLSearchParams(yield* request.text).getAll("resource");

          if (resources.length !== 1 || !(yield* service.resources.get(resources[0] ?? "")))
            return json(
              {
                error: "invalid_target",
                error_description: "Exactly one configured resource is required",
              },
              400,
            );
        }

        const body =
          request.method === "GET" || request.method === "HEAD"
            ? undefined
            : yield* request.arrayBuffer;

        const response = yield* provider(() =>
          auth.handler(
            new Request(url, { method: request.method, headers: request.headers, body }),
          ),
        );

        return HttpServerResponse.fromWeb(response);
      }).pipe(Effect.catch(respond));

      // The built dashboard: one HTML document and its hashed script and stylesheet.
      const staticRoutes = HttpRouter.use((router) =>
        Effect.gen(function* () {
          const platform = yield* HttpPlatform.HttpPlatform;
          yield* router.add(
            "*",
            "/*",
            Effect.gen(function* () {
              const request = yield* HttpServerRequest.HttpServerRequest;

              if (request.method !== "GET" && request.method !== "HEAD") return notFound;
              const path = new URL(request.url, settings.baseURL).pathname;

              const file = spaRoutes.has(path)
                ? "index.html"
                : assetPath.test(path)
                  ? path.slice(1)
                  : undefined;

              if (!file) return notFound;

              return yield* platform
                .fileResponse(resolve(staticRoot, file), {
                  contentType: file.endsWith(".js")
                    ? "text/javascript"
                    : file.endsWith(".css")
                      ? "text/css"
                      : "text/html; charset=utf-8",
                })
                .pipe(Effect.catch(() => Effect.succeed(notFound)));
            }),
          );
        }),
      );

      const policy = HttpRouter.middleware(
        (handler) =>
          requestPolicy({ baseURL: settings.baseURL, trustProxy: settings.trustProxy })(
            Effect.gen(function* () {
              const request = yield* HttpServerRequest.HttpServerRequest;
              const pathname = new URL(request.url, settings.baseURL).pathname;
              const path = pathname.replace(/^\/api\/auth/, "");
              const isMcp = pathname === "/mcp";
              const origin = request.headers.origin;
              const mcpOriginAllowed = origin !== undefined && mcpAllowedOrigins.includes(origin);
              const publicCors = corsPaths.has(path);
              let response: HttpServerResponse.HttpServerResponse;

              if (isMcp && origin !== undefined && !mcpOriginAllowed) {
                response = json({ error: "Invalid origin" }, 403);
              } else if (isMcp && request.method === "OPTIONS") {
                const method = request.headers["access-control-request-method"];

                const headers = (request.headers["access-control-request-headers"] ?? "")
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

              if (publicCors)
                response = response.pipe(
                  HttpServerResponse.setHeaders({
                    "access-control-allow-origin": "*",
                    "access-control-allow-methods": "GET, POST, OPTIONS",
                    "access-control-allow-headers": "Authorization, Content-Type, DPoP",
                    "access-control-expose-headers": "WWW-Authenticate, DPoP-Nonce",
                  }),
                  HttpServerResponse.removeHeader("access-control-allow-credentials"),
                );

              if (isMcp) {
                response = response.pipe(
                  HttpServerResponse.setHeader(
                    "vary",
                    response.headers.vary ? `${response.headers.vary}, Origin` : "Origin",
                  ),
                  HttpServerResponse.removeHeader("access-control-allow-credentials"),
                );

                if (mcpOriginAllowed && origin !== undefined) {
                  response = response.pipe(
                    HttpServerResponse.setHeaders({
                      "access-control-allow-origin": origin,
                      "access-control-expose-headers": "WWW-Authenticate, Mcp-Protocol-Version",
                    }),
                  );

                  if (
                    request.method === "OPTIONS" &&
                    response.status >= 200 &&
                    response.status < 300
                  )
                    response = response.pipe(
                      HttpServerResponse.setHeaders({
                        "access-control-allow-methods": "POST",
                        "access-control-allow-headers": mcpRequestHeaders.join(", "),
                      }),
                    );
                }
              }

              const cacheable = request.method === "GET" && response.status === 200;

              const cacheControl = !cacheable
                ? "no-store"
                : pathname.startsWith("/assets/")
                  ? "public, max-age=31536000, immutable"
                  : cacheablePaths.has(path)
                    ? "public, max-age=300"
                    : "no-store";

              response = response.pipe(
                HttpServerResponse.setHeaders({
                  "cache-control": cacheControl,
                  "referrer-policy": "no-referrer",
                  "x-content-type-options": "nosniff",
                  "x-frame-options": "DENY",
                  "content-security-policy":
                    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                }),
              );

              if (settings.baseURL.startsWith("https:"))
                response = response.pipe(
                  HttpServerResponse.setHeader("strict-transport-security", "max-age=31536000"),
                );

              return response;
            }),
          ),
        { global: true },
      );

      // Nothing the provider does can be cancelled, so no handler is: a disconnect or
      // shutdown interrupts a request only once its work is done, and the request fiber
      // owns every provider call it made, which is what lets shutdown wait for them all.
      // Route middleware, because the router re-enters interruptibility per route.
      const uninterruptible = HttpRouter.middleware((handler) => Effect.uninterruptible(handler));

      return Layer.mergeAll(
        actionRoutes(mcpAllowedOrigins),
        settings.cookieDomain === undefined
          ? Layer.empty
          : forwardAuthRoutes(settings.cookieDomain),
        HttpRouter.add(
          "GET",
          "/healthz",
          service.sql`SELECT 1`.pipe(Effect.as(json({ status: "ok" })), Effect.catch(respond)),
        ),
        HttpRouter.add("*", "/api/auth/*", bridge),
        HttpRouter.add("*", "/.well-known/*", bridge),
        staticRoutes,
      ).pipe(
        Layer.provide(uninterruptible.layer),
        // Register the outer policy first: discovery is itself short-circuiting global
        // middleware and must not bypass input limits, CORS, or security headers.
        Layer.provide(policy),
        Layer.provide(NodeHttpServer.layerHttpServices),
      );
    }),
  );

/** Attach the same native routes to an already-bound development/test server. */
export const nodeHandler = Effect.fn("Http.nodeHandler")(function* (staticRoot?: string) {
  const handler = yield* HttpRouter.toHttpEffect(application(staticRoot));

  return yield* NodeHttpServer.makeHandler(handler, { scope: yield* Effect.scope });
});
