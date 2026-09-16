import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Effect, Schema } from "effect";
import { APIError } from "better-auth/api";
import type { Service } from "./auth.ts";
import { actionApi } from "./action-api.ts";

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
const json = (body: unknown, status = 200) => Response.json(body, { status });
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

export function application(
  service: Service,
  staticRoot = fileURLToPath(
    new URL("dist/", import.meta.resolve("@clankerauth/web/package.json")),
  ),
) {
  const { auth, settings } = service;
  // The same exact allowlist governs CORS and native MCP Origin admission.
  const mcpAllowedOrigins = [...new Set([settings.baseURL, ...(settings.mcpAllowedOrigins ?? [])])];
  const api = actionApi(service, mcpAllowedOrigins);
  async function dispatch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/healthz" && req.method === "GET") {
      await Effect.runPromise(service.sql`SELECT 1`);
      return json({ status: "ok" });
    }
    // Custom actions are POST /api/<name>. OAuth remains under /api/auth.
    if (
      (url.pathname.startsWith("/api/") &&
        url.pathname !== "/api/auth" &&
        !url.pathname.startsWith("/api/auth/")) ||
      url.pathname === "/openapi.json" ||
      url.pathname === "/mcp" ||
      url.pathname === "/.well-known/oauth-protected-resource/mcp"
    )
      return api.handler(req);
    if (url.pathname.startsWith("/api/auth/") || url.pathname.startsWith("/.well-known/")) {
      const path = url.pathname.replace(/^\/api\/auth/, "");
      if (!publicPaths.has(path) && path !== "/.well-known/oauth-authorization-server/api/auth")
        return json({ error: "Not found" }, 404);
      // This service intentionally issues one-resource access tokens. Never fall back to opaque/unbound tokens.
      if (path === "/oauth2/authorize" || path === "/oauth2/token") {
        let resources: string[];
        if (req.method === "GET") resources = url.searchParams.getAll("resource");
        else if (req.headers.get("content-type")?.includes("application/json")) {
          const body = Schema.decodeUnknownOption(ResourceRequest)(await req.clone().json());
          resources = body._tag === "Some" ? [body.value.resource] : [];
        } else resources = new URLSearchParams(await req.clone().text()).getAll("resource");
        if (
          resources.length !== 1 ||
          !(await Effect.runPromise(service.resources.get(resources[0] ?? "")))
        ) {
          return json(
            {
              error: "invalid_target",
              error_description: "Exactly one configured resource is required",
            },
            400,
          );
        }
      }
      return auth.handler(req);
    }
    if (req.method !== "GET" && req.method !== "HEAD") return json({ error: "Not found" }, 404);
    let file: string;
    if (["/", "/login", "/consent", "/setup"].includes(url.pathname)) file = "index.html";
    else if (/^\/assets\/[a-zA-Z0-9_.-]+\.(js|css)$/.test(url.pathname))
      file = url.pathname.slice(1);
    else return json({ error: "Not found" }, 404);
    const content = await readFile(resolve(staticRoot, file));
    return new Response(req.method === "HEAD" ? null : content, {
      headers: {
        "content-type": file.endsWith(".js")
          ? "text/javascript"
          : file.endsWith(".css")
            ? "text/css"
            : "text/html; charset=utf-8",
      },
    });
  }
  const handle = async (req: Request) => {
    const pathname = new URL(req.url).pathname;
    const path = pathname.replace(/^\/api\/auth/, "");
    const isMcp = pathname === "/mcp";
    const origin = req.headers.get("origin");
    const mcpOriginAllowed = origin !== null && mcpAllowedOrigins.includes(origin);
    const publicCors = corsPaths.has(path);
    let response: Response;
    try {
      if (isMcp && origin !== null && !mcpOriginAllowed) {
        response = json({ error: "Invalid origin" }, 403);
      } else if (isMcp && req.method === "OPTIONS") {
        const method = req.headers.get("access-control-request-method");
        const headers = (req.headers.get("access-control-request-headers") ?? "")
          .split(",")
          .map((header) => header.trim().toLowerCase())
          .filter(Boolean);
        response =
          mcpOriginAllowed &&
          method !== null &&
          mcpMethods.includes(method) &&
          headers.every((header) => mcpRequestHeaderNames.has(header))
            ? new Response(null, { status: 204 })
            : json({ error: "MCP preflight rejected" }, 403);
      } else {
        response =
          publicCors && req.method === "OPTIONS"
            ? new Response(null, { status: 204 })
            : await service.run(() => dispatch(req));
      }
    } catch (error) {
      const status =
        error instanceof APIError
          ? error.statusCode
          : Schema.isSchemaError(error) || error instanceof SyntaxError
            ? 400
            : 500;
      response = json(
        { error: status === 401 ? "Authentication required" : "Request could not be completed" },
        status,
      );
    }
    if (publicCors) {
      response.headers.set("access-control-allow-origin", "*");
      response.headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
      response.headers.set("access-control-allow-headers", "Authorization, Content-Type, DPoP");
      response.headers.set("access-control-expose-headers", "WWW-Authenticate, DPoP-Nonce");
      response.headers.delete("access-control-allow-credentials");
    }
    if (isMcp) {
      response.headers.append("vary", "Origin");
      response.headers.delete("access-control-allow-credentials");
      if (mcpOriginAllowed && origin !== null) {
        response.headers.set("access-control-allow-origin", origin);
        response.headers.set(
          "access-control-expose-headers",
          "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version",
        );
        if (req.method === "OPTIONS" && response.ok) {
          response.headers.set("access-control-allow-methods", mcpMethods.join(", "));
          response.headers.set("access-control-allow-headers", mcpRequestHeaders.join(", "));
        }
      }
    }
    response.headers.set("cache-control", "no-store");
    response.headers.set("referrer-policy", "no-referrer");
    response.headers.set("x-content-type-options", "nosniff");
    response.headers.set("x-frame-options", "DENY");
    response.headers.set(
      "content-security-policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    if (settings.baseURL.startsWith("https:"))
      response.headers.set("strict-transport-security", "max-age=31536000");
    return response;
  };
  return Object.assign(handle, { dispose: api.dispose });
}
