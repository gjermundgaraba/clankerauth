import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Schema } from "effect";
import { APIError } from "better-auth/api";
import type { Service } from "./auth.ts";

const ClientInput = Schema.Struct({
  name: Schema.String,
  redirect: Schema.String,
  resource: Schema.String,
  confidential: Schema.Boolean,
  native: Schema.Boolean,
});
const ClientId = Schema.Struct({ client_id: Schema.String });
const ResourceRequest = Schema.Struct({ resource: Schema.String });
const publicPaths = new Set([
  "/sign-in/email",
  "/sign-out",
  "/get-session",
  "/change-password",
  "/jwks",
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
const json = (body: unknown, status = 200) => Response.json(body, { status });

export function application(
  service: Service,
  staticRoot = fileURLToPath(
    new URL("dist/", import.meta.resolve("@clankerauth/web/package.json")),
  ),
) {
  const { auth, settings } = service;
  async function dispatch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/healthz" && req.method === "GET") {
      service.db.prepare("SELECT 1").get();
      return json({ status: "ok" });
    }
    if (url.pathname.startsWith("/admin/")) {
      const session = await auth.api.getSession({ headers: req.headers });
      if (!session || session.user.id !== service.owner())
        return json({ error: "Owner session required" }, 401);
      if (req.method !== "GET" && req.headers.get("origin") !== settings.baseURL)
        return json({ error: "Invalid origin" }, 403);
      if (req.method !== "GET" && Date.now() - session.session.createdAt.getTime() > 15 * 60 * 1000)
        return json({ error: "Sign out and sign in again before changing clients" }, 403);
      if (url.pathname === "/admin/clients" && req.method === "GET") {
        return json({
          clients: await auth.api.getOAuthClients({ headers: req.headers }),
          resources: settings.resources,
          email: session.user.email,
          issuer: `${settings.baseURL}/api/auth`,
        });
      }
      if (url.pathname === "/admin/clients" && req.method === "POST") {
        const input = Schema.decodeUnknownSync(ClientInput)(await req.json());
        const resource = settings.resources.find((r) => r.identifier === input.resource);
        if (!resource || !input.name.trim() || input.name.length > 100)
          return json({ error: "Invalid client name or resource" }, 400);
        const client = await auth.api.createOAuthClient({
          headers: req.headers,
          body: {
            client_name: input.name.trim(),
            redirect_uris: [input.redirect],
            token_endpoint_auth_method: input.confidential ? "client_secret_basic" : "none",
            application_type: input.native ? "native" : "web",
            grant_types: ["authorization_code", "refresh_token"],
            scope: ["openid", "profile", "email", "offline_access", ...resource.scopes].join(" "),
          },
        });
        try {
          await auth.api.adminLinkClientResource({
            headers: req.headers,
            params: { identifier: resource.identifier, client_id: client.client_id },
          });
        } catch (error) {
          await auth.api.deleteOAuthClient({
            headers: req.headers,
            body: { client_id: client.client_id },
          });
          throw error;
        }
        return json(client, 201);
      }
      if (
        req.method === "POST" &&
        ["/admin/clients/delete", "/admin/clients/rotate"].includes(url.pathname)
      ) {
        const body = Schema.decodeUnknownSync(ClientId)(await req.json());
        if (url.pathname.endsWith("/rotate"))
          return json(await auth.api.rotateClientSecret({ headers: req.headers, body }));
        await auth.api.deleteOAuthClient({ headers: req.headers, body });
        return json({ deleted: true });
      }
      return json({ error: "Not found" }, 404);
    }
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
          !settings.resources.some((r) => r.identifier === resources[0])
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
    if (["/", "/login", "/consent"].includes(url.pathname)) file = "index.html";
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
  return async (req: Request) => {
    const path = new URL(req.url).pathname.replace(/^\/api\/auth/, "");
    const publicCors =
      [
        "/jwks",
        "/oauth2/token",
        "/oauth2/revoke",
        "/oauth2/introspect",
        "/oauth2/userinfo",
      ].includes(path) ||
      [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/api/auth",
        "/.well-known/openid-configuration",
      ].includes(path);
    let response: Response;
    try {
      response =
        publicCors && req.method === "OPTIONS"
          ? new Response(null, { status: 204 })
          : await service.exclusive(() => dispatch(req));
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
}
