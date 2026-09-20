/**
 * Forward auth: a reverse proxy asks this issuer on every browser request. A signed-in
 * owner gets a short-lived access token for the app's resource in an Authorization header,
 * which the proxy copies upstream; anyone else is sent through the issuer and back.
 * The app verifies that token exactly as it verifies MCP and API-key bearer tokens.
 *
 * The owner's issuer session cookie never leaves the issuer host. Apps see only the
 * forward cookie: the session cookie value encrypted under the server secret, accepted
 * by these routes alone. It resolves to the live session, so sign-out revokes it.
 */
import { Effect, Layer, Option, Redacted } from "effect";
import { Cookies, HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import { createAuthEndpoint } from "better-auth/api";
import type { BetterAuthPlugin } from "better-auth";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { signJWT, type JwtOptions } from "better-auth/plugins/jwt";
import * as z from "zod";
import { allowedScheme, withinDomain } from "./config.ts";
import { apiError, apiErrorResponse, provider } from "./api-errors.ts";
import { mcpResource } from "./resources.ts";
import type { Service } from "./auth.ts";

/** The `client_id` claim of forward-auth tokens. Not a registered client: administration
 * MCP joins tokens to the client table, so these tokens can never administer the issuer. */
export const forwardClientId = "forward-auth";

export const forwardCookie = "clankerauth_forward";

const TokenRequest = z.object({ subject: z.string(), audience: z.string(), scope: z.string() });

/** Signs access tokens outside the OAuth flows, with the JWT plugin's key and the same
 * profile the provider uses for its own access tokens. Server-only: never routed. */
export const forwardTokens = (jwt: JwtOptions, lifetimeSeconds: number) =>
  ({
    id: "forward-tokens",
    endpoints: {
      signForwardToken: createAuthEndpoint.serverOnly(
        { method: "POST", body: TokenRequest },
        async (ctx) => {
          const iat = Math.floor(Date.now() / 1000);

          const token = await signJWT(ctx, {
            options: jwt,
            header: { typ: "at+jwt" },
            payload: {
              sub: ctx.body.subject,
              aud: ctx.body.audience,
              client_id: forwardClientId,
              scope: ctx.body.scope,
              iat,
              exp: iat + lifetimeSeconds,
            },
          });

          return ctx.json({ token });
        },
      ),
    },
  }) satisfies BetterAuthPlugin;

const json = (status: number, error: string) =>
  HttpServerResponse.jsonUnsafe({ error }, { status });

/** Forward auth exists to share one owner session across a cookie domain, so it needs one. */
export const forwardAuthRoutes = (service: Service, cookieDomain: string) => {
  const { settings } = service;

  /** Return only where the forward cookie reaches, under the issuer's own scheme policy. */
  const allowedReturnURL = (value: string) => {
    if (!URL.canParse(value)) return undefined;
    const url = new URL(value);

    return !url.username &&
      !url.password &&
      allowedScheme(url, settings.allowInsecureHttp) &&
      withinDomain(url.hostname, cookieDomain)
      ? url
      : undefined;
  };

  const secret = Redacted.value(settings.secret);
  const reserved = mcpResource(settings.baseURL);
  const loginPage = new URL("/login", settings.baseURL);

  const cookieOptions = {
    domain: cookieDomain,
    path: "/",
    httpOnly: true,
    secure: settings.baseURL.startsWith("https:"),
    sameSite: "lax",
  } as const;

  const sessionCookieName = Effect.tryPromise(async () => {
    const context = await service.auth.$context;

    return context.authCookies.sessionToken.name;
  });

  const withReturn = (path: string, returnTo: URL) => {
    const url = new URL(path, settings.baseURL);
    url.searchParams.set("rd", returnTo.href);

    return url;
  };

  const session = (cookie: string) =>
    provider(() => service.auth.api.getSession({ headers: new Headers({ cookie }) }));

  const check = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const { headers } = request;

    const proto = headers["x-forwarded-proto"];
    const host = headers["x-forwarded-host"];

    const returnTo =
      proto && host
        ? allowedReturnURL(`${proto}://${host}${headers["x-forwarded-uri"] ?? "/"}`)
        : undefined;

    if (!returnTo) return json(400, "invalid_forwarded_request");
    const identifier = new URL(request.url, settings.baseURL).searchParams.get("resource");

    const resource =
      identifier && identifier !== reserved && (yield* service.resources.get(identifier));

    if (!resource) return json(403, "unknown_resource");
    const sealed = request.cookies[forwardCookie];

    // A missing, tampered or foreign cookie is simply not a session.
    const unsealed = sealed
      ? yield* Effect.option(
          Effect.tryPromise(() => symmetricDecrypt({ key: secret, data: sealed })),
        )
      : Option.none();

    const current = Option.isSome(unsealed)
      ? yield* session(`${yield* sessionCookieName}=${unsealed.value}`)
      : null;

    // Only a page navigation can follow the issuer and come back. A script's request would
    // chase the redirect across origins and fail opaquely, so it gets a plain refusal.
    if (!current)
      return headers["sec-fetch-mode"] === "navigate"
        ? HttpServerResponse.redirect(withReturn("/forward-auth/continue", returnTo))
        : json(401, "unauthenticated");

    const { token } = yield* provider(() =>
      service.auth.api.signForwardToken({
        body: {
          subject: current.user.id,
          audience: resource.identifier,
          scope: resource.scopes.join(" "),
        },
      }),
    );

    return HttpServerResponse.empty({
      status: 204,
      headers: { authorization: `Bearer ${token}` },
    });
  });

  /** On the issuer host, where the session cookie is visible: seal it into the forward
   * cookie and go back to the app, or sign in first. */
  const proceed = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const requested = new URL(request.url, settings.baseURL).searchParams.get("rd");
    const returnTo = requested ? allowedReturnURL(requested) : undefined;

    if (!returnTo) return json(400, "invalid_return_url");
    const value = request.cookies[yield* sessionCookieName];
    const current = value ? yield* session(request.headers.cookie ?? "") : null;

    // Login returns only to this origin: back here, which then seals the cookie and goes on.
    if (!current || !value)
      return HttpServerResponse.redirect(
        withReturn("/login", withReturn("/forward-auth/continue", returnTo)),
      );
    const sealed = yield* Effect.tryPromise(() => symmetricEncrypt({ key: secret, data: value }));

    // A browser-session cookie: renewing it is two redirects while the issuer session lives.
    return yield* HttpServerResponse.redirect(returnTo).pipe(
      HttpServerResponse.setCookie(forwardCookie, sealed, cookieOptions),
    );
  });

  const logout = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const requested = new URL(request.url, settings.baseURL).searchParams.get("rd");
    const returnTo = (requested && allowedReturnURL(requested)) || loginPage;

    // Sign-out ends the session and clears its cookie whether or not one exists.
    const { headers } = yield* provider(() =>
      service.auth.api.signOut({
        headers: new Headers({ cookie: request.headers.cookie ?? "" }),
        returnHeaders: true,
      }),
    );

    return yield* HttpServerResponse.mergeCookies(
      HttpServerResponse.redirect(returnTo),
      Cookies.fromSetCookie(headers.getSetCookie()),
    ).pipe(HttpServerResponse.setCookie(forwardCookie, "", { ...cookieOptions, maxAge: 0 }));
  });

  const publicErrors = <A, R>(effect: Effect.Effect<A, unknown, R>) =>
    effect.pipe(Effect.catch((error) => apiErrorResponse(apiError(error))));

  return Layer.mergeAll(
    HttpRouter.add("GET", "/forward-auth", publicErrors(check)),
    HttpRouter.add("GET", "/forward-auth/continue", publicErrors(proceed)),
    HttpRouter.add("GET", "/forward-auth/logout", publicErrors(logout)),
  );
};
