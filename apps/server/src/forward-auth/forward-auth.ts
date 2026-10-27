import {
  returnToParameter,
  signOutPath,
} from "@gjermundgaraba/clankerauth-sdk/session";
import { Clock, Effect, Layer, Option, Redacted } from "effect";
import {
  Cookies,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/http";

import { seal, unseal } from "../issuer/cookies.ts";
import {
  provider,
  refusal,
  respond,
  unavailability,
} from "../issuer/errors.ts";
import { accessTokenLifetime, Issuer } from "../issuer/issuer.ts";
import { allowedScheme, Settings, withinDomain } from "../issuer/settings.ts";
import { ResourceCatalog } from "../resources/catalog.ts";

// why: an empty header, cookie or parameter counts as absent, as an absent one does
const nonEmpty = (value: string | null | undefined): value is string =>
  value !== undefined && value !== null && value !== "";

export const forwardClientId = "forward-auth";

export const forwardCookie = "clankerauth_forward";

const json = (status: number, error: string) =>
  HttpServerResponse.jsonUnsafe({ error }, { status });

export const forwardAuthRoutes = (cookieDomain: string) =>
  Layer.unwrap(
    Effect.gen(function* () {
      const settings = yield* Settings;
      const { auth, context } = yield* Issuer;
      const catalog = yield* ResourceCatalog;

      const allowedReturnURL = (value: string) => {
        if (!URL.canParse(value)) {
          return;
        }

        const url = new URL(value);

        return !url.username &&
          !url.password &&
          allowedScheme(url, settings.allowInsecureHttp) &&
          withinDomain(url.hostname, cookieDomain)
          ? url
          : undefined;
      };

      const secret = Redacted.value(settings.secret);
      const loginPage = new URL("/login", settings.baseURL);

      const cookieOptions = {
        domain: cookieDomain,
        path: "/",
        httpOnly: true,
        secure: settings.baseURL.startsWith("https:"),
        sameSite: "lax",
      } as const;

      const sessionCookieName = context.authCookies.sessionToken.name;

      const withReturn = (path: string, returnTo: URL) => {
        const url = new URL(path, settings.baseURL);
        url.searchParams.set(returnToParameter, returnTo.href);

        return url;
      };

      const session = (cookie: string) =>
        provider(
          async () =>
            await auth.api.getSession({ headers: new Headers({ cookie }) }),
          {
            unavailable: unavailability,
          }
        );

      const check = Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const { headers } = request;

        const proto = headers["x-forwarded-proto"];
        const host = headers["x-forwarded-host"];

        const returnTo =
          nonEmpty(proto) && nonEmpty(host)
            ? allowedReturnURL(
                `${proto}://${host}${headers["x-forwarded-uri"] ?? "/"}`
              )
            : undefined;

        if (!returnTo) {
          return json(400, "invalid_forwarded_request");
        }

        const identifier = new URL(
          request.url,
          settings.baseURL
        ).searchParams.get("resource");

        const resource = nonEmpty(identifier)
          ? yield* catalog.application(identifier)
          : undefined;

        if (!resource) {
          return json(403, "unknown_resource");
        }

        const sealed = request.cookies[forwardCookie];

        const unsealed = nonEmpty(sealed)
          ? yield* Effect.option(unseal(secret, sealed))
          : Option.none();

        const current = Option.isSome(unsealed)
          ? yield* session(`${sessionCookieName}=${unsealed.value}`)
          : null;

        if (!current) {
          return headers["sec-fetch-mode"] === "navigate"
            ? HttpServerResponse.redirect(
                withReturn("/forward-auth/continue", returnTo)
              )
            : json(401, "unauthenticated");
        }

        const iat = Math.floor((yield* Clock.currentTimeMillis) / 1000);

        const { token } = yield* provider(
          async () =>
            await auth.api.signDocument({
              body: {
                typ: "at+jwt",
                payload: {
                  sub: current.user.id,
                  aud: resource.identifier,
                  client_id: forwardClientId,
                  scope: resource.scopes.join(" "),
                  iat,
                  exp: iat + accessTokenLifetime,
                },
              },
            })
        );

        return HttpServerResponse.empty({
          status: 204,
          headers: { authorization: `Bearer ${token}` },
        });
      });

      const proceed = Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;

        const requested = new URL(
          request.url,
          settings.baseURL
        ).searchParams.get(returnToParameter);

        const returnTo = nonEmpty(requested)
          ? allowedReturnURL(requested)
          : undefined;

        if (!returnTo) {
          return json(400, "invalid_return_url");
        }

        const value = request.cookies[sessionCookieName];

        const current = nonEmpty(value)
          ? yield* session(request.headers["cookie"] ?? "")
          : null;

        if (!current || !nonEmpty(value)) {
          return HttpServerResponse.redirect(
            withReturn("/login", withReturn("/forward-auth/continue", returnTo))
          );
        }

        const sealed = yield* seal(secret, value);

        return yield* HttpServerResponse.redirect(returnTo).pipe(
          HttpServerResponse.setCookie(forwardCookie, sealed, cookieOptions)
        );
      });

      const logout = Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;

        const requested = new URL(
          request.url,
          settings.baseURL
        ).searchParams.get(returnToParameter);

        const returnTo =
          (nonEmpty(requested) ? allowedReturnURL(requested) : undefined) ??
          loginPage;

        const { headers } = yield* provider(
          async () =>
            await auth.api.signOut({
              headers: new Headers({ cookie: request.headers["cookie"] ?? "" }),
              returnHeaders: true,
            }),
          { refused: refusal, unavailable: unavailability }
        );

        return yield* HttpServerResponse.mergeCookies(
          HttpServerResponse.redirect(returnTo),
          Cookies.fromSetCookie(headers.getSetCookie())
        ).pipe(
          HttpServerResponse.setCookie(forwardCookie, "", {
            ...cookieOptions,
            maxAge: 0,
          })
        );
      });

      return Layer.mergeAll(
        HttpRouter.add(
          "GET",
          "/forward-auth",
          check.pipe(Effect.catch(respond))
        ),
        HttpRouter.add(
          "GET",
          "/forward-auth/continue",
          proceed.pipe(Effect.catch(respond))
        ),
        HttpRouter.add("GET", signOutPath, logout.pipe(Effect.catch(respond)))
      );
    })
  );
