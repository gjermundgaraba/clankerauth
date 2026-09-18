import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Effect, Layer, Option, Result, Schema } from "effect";
import { NodeHttpServer } from "@effect/platform-node";
import {
  HttpPlatform,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";
import { APIError } from "better-auth/api";
import type { Service } from "./auth.ts";
import { actionRoutes } from "./action-api.ts";
import { requestPolicy } from "./node-http.ts";

const ResourceRequest = Schema.Struct({ resource: Schema.String });

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
  "/oauth2/userinfo",
  "/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server",
]);

const corsPaths = new Set([
  "/.well-known/oauth-protected-resource/mcp",
  "/jwks",
  "/oauth2/register",
  "/oauth2/token",
  "/oauth2/revoke",
  "/oauth2/introspect",
  "/oauth2/userinfo",
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-authorization-server/api/auth",
  "/.well-known/openid-configuration",
]);

const json = (body: typeof Schema.Json.Type, status = 200) =>
  HttpServerResponse.jsonUnsafe(body, { status });

const mcpMethods = ["GET", "POST", "DELETE"];

const mcpRequestHeaders = [
  "Authorization",
  "Content-Type",
  "Accept",
  "Mcp-Protocol-Version",
  "Mcp-Session-Id",
  "Mcp-Method",
  "Mcp-Name",
  "Last-Event-ID",
];

const mcpRequestHeaderNames = new Set(mcpRequestHeaders.map((header) => header.toLowerCase()));

const errorResponse = (error: Error) => {
  const status =
    error instanceof APIError
      ? error.statusCode
      : Schema.isSchemaError(error) || error instanceof SyntaxError
        ? 400
        : 500;

  return Effect.succeed(
    json(
      { error: status === 401 ? "Authentication required" : "Request could not be completed" },
      status,
    ),
  );
};

/** All routes remain native Effect HTTP, except the Better Auth adapter. */
export function application(
  service: Service,
  staticRoot = fileURLToPath(
    new URL("dist/", import.meta.resolve("@clankerauth/web/package.json")),
  ),
) {
  const { auth, settings } = service;
  const mcpAllowedOrigins = [...new Set([settings.baseURL, ...(settings.mcpAllowedOrigins ?? [])])];

  const provider = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const url = new URL(request.url, settings.baseURL);
    const path = url.pathname.replace(/^\/api\/auth/, "");

    if (!publicPaths.has(path) && path !== "/.well-known/oauth-authorization-server/api/auth")
      return json({ error: "Not found" }, 404);

    // Our one-resource policy is enforced before entering the OAuth provider.
    if (path === "/oauth2/authorize" || path === "/oauth2/token") {
      let resources: string[];

      if (request.method === "GET") resources = url.searchParams.getAll("resource");
      else if (request.headers["content-type"]?.includes("application/json")) {
        const body = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Unknown))(
          yield* request.text,
        );

        const resource = Schema.decodeUnknownOption(ResourceRequest)(body);
        resources = Option.isSome(resource) ? [resource.value.resource] : [];
      } else resources = new URLSearchParams(yield* request.text).getAll("resource");

      if (
        resources.length !== 1 ||
        !(yield* service.resources.get(resources[0] ?? "").pipe(Effect.uninterruptible))
      )
        return json(
          {
            error: "invalid_target",
            error_description: "Exactly one configured resource is required",
          },
          400,
        );
    }

    // Pass disconnect cancellation into the Web request, but track the actual
    // provider Promise until settlement even when the Effect caller is interrupted.
    const body =
      request.method === "GET" || request.method === "HEAD"
        ? undefined
        : yield* request.arrayBuffer;

    const response = yield* Effect.tryPromise({
      try: (signal) =>
        service.run(async () => {
          const response = await auth.handler(
            new Request(url, {
              method: request.method,
              headers: request.headers,
              body,
              signal,
            }),
          );

          // A provider can settle after its caller disconnects. Release that body too.
          if (signal.aborted) await response.body?.cancel();

          return response;
        }),
      catch: (cause) => (cause instanceof Error ? cause : new Error(String(cause))),
    });

    return HttpServerResponse.fromWeb(response);
  }).pipe(Effect.catch(errorResponse));

  const staticRoutes = HttpRouter.use((router) =>
    Effect.gen(function* () {
      const platform = yield* HttpPlatform.HttpPlatform;
      yield* router.add(
        "*",
        "/*",
        Effect.gen(function* () {
          const request = yield* HttpServerRequest.HttpServerRequest;

          if (request.method !== "GET" && request.method !== "HEAD")
            return json({ error: "Not found" }, 404);
          const path = new URL(request.url, settings.baseURL).pathname;

          const file = ["/", "/login", "/consent", "/setup"].includes(path)
            ? "index.html"
            : /^\/assets\/[a-zA-Z0-9_.-]+\.(js|css)$/.test(path)
              ? path.slice(1)
              : undefined;

          if (!file) return json({ error: "Not found" }, 404);

          return yield* platform.fileResponse(resolve(staticRoot, file), {
            contentType: file.endsWith(".js")
              ? "text/javascript"
              : file.endsWith(".css")
                ? "text/css"
                : "text/html; charset=utf-8",
          });
        }).pipe(Effect.catch(errorResponse)),
      );
    }),
  );

  const policy = HttpRouter.middleware(
    (handler) =>
      requestPolicy(settings.baseURL)(
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
              method !== undefined &&
              mcpMethods.includes(method) &&
              headers.every((header) => mcpRequestHeaderNames.has(header))
                ? HttpServerResponse.empty({ status: 204 })
                : json({ error: "MCP preflight rejected" }, 403);
          } else if (publicCors && request.method === "OPTIONS") {
            response = HttpServerResponse.empty({ status: 204 });
          } else {
            // Request scopes include response streaming and asynchronous provider finalizers.
            const admitted = yield* Effect.acquireRelease(
              Effect.try({ try: service.retain, catch: (cause) => cause }),
              (release) => Effect.sync(release),
            ).pipe(Effect.result);

            response = Result.isFailure(admitted)
              ? json({ error: "Request could not be completed" }, 503)
              : yield* handler;
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
                  "access-control-expose-headers":
                    "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version",
                }),
              );

              if (request.method === "OPTIONS" && response.status >= 200 && response.status < 300)
                response = response.pipe(
                  HttpServerResponse.setHeaders({
                    "access-control-allow-methods": mcpMethods.join(", "),
                    "access-control-allow-headers": mcpRequestHeaders.join(", "),
                  }),
                );
            }
          }

          response = response.pipe(
            HttpServerResponse.setHeaders({
              "cache-control": "no-store",
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

  return Layer.mergeAll(
    actionRoutes(service, mcpAllowedOrigins),
    HttpRouter.add(
      "GET",
      "/healthz",
      service.sql`SELECT 1`.pipe(
        Effect.as(json({ status: "ok" })),
        Effect.uninterruptible,
        Effect.catch(errorResponse),
      ),
    ),
    HttpRouter.add("*", "/api/auth/*", provider),
    HttpRouter.add("*", "/.well-known/*", provider),
    staticRoutes,
  ).pipe(
    // Register the outer policy first: discovery is itself short-circuiting global
    // middleware and must not bypass input limits, CORS, or security headers.
    Layer.provide(policy),
    Layer.provide(NodeHttpServer.layerHttpServices),
  );
}

/** Attach the same native routes to an already-bound development/test server. */
export const nodeHandler = Effect.fn("Http.nodeHandler")(function* (
  service: Service,
  staticRoot?: string,
) {
  const handler = yield* HttpRouter.toHttpEffect(application(service, staticRoot));

  return yield* NodeHttpServer.makeHandler(handler, { scope: yield* Effect.scope });
});
