import { Actions, Http } from "./browser-api.ts";
import { Duration, Effect, Layer } from "effect";
import {
  HttpEffect,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";
import { transactionLifetime, type BrowserSession } from "./browser.ts";
import { authenticationErrors, encodeError, InvalidRequest } from "./errors.ts";

const encode = encodeError([...authenticationErrors, InvalidRequest]);

/** Login, session and logout actions under `/auth/browser`, plus the OAuth callback route. */
export const layer = (browser: BrowserSession) => {
  const cookie = (suffix: string, value: string, age: number) =>
    HttpServerResponse.setCookieUnsafe(`${browser.cookie.name}_${suffix}`, value, {
      path: "/",
      httpOnly: true,
      sameSite: "lax",
      secure: browser.cookie.secure,
      maxAge: Duration.seconds(age),
    });

  const setCookie = (suffix: string, value: string, age: number) =>
    HttpEffect.appendPreResponseHandler((_request, response) =>
      Effect.succeed(cookie(suffix, value, age)(response)),
    );

  const sameOrigin = Effect.flatMap(HttpServerRequest.HttpServerRequest, (request) =>
    browser.checkOrigin(request.headers.origin),
  );

  const sessionCookie = Effect.map(
    HttpServerRequest.HttpServerRequest,
    (request) => request.cookies[`${browser.cookie.name}_session`],
  );

  const actions = Actions.implement({
    login: ({ returnTo }) =>
      Effect.gen(function* () {
        yield* sameOrigin;
        const result = yield* browser.login(returnTo);
        yield* setCookie("login", result.transaction, transactionLifetime);

        return { url: result.url };
      }),
    session: () =>
      Effect.gen(function* () {
        yield* sameOrigin;

        return yield* browser.session(yield* sessionCookie);
      }),
    logout: () =>
      Effect.gen(function* () {
        yield* sameOrigin;
        yield* browser.logout(yield* sessionCookie);
        yield* setCookie("session", "", 0);

        return {};
      }),
  });

  const callback = Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;

    const url = yield* Effect.try({
      try: () => new URL(request.originalUrl, browser.origin),
      catch: () => new InvalidRequest({ message: "Invalid callback URL" }),
    });

    const result = yield* browser.callback(url, request.cookies[`${browser.cookie.name}_login`]);

    return HttpServerResponse.redirect(result.location, { status: 302 }).pipe(
      cookie("session", result.session, browser.cookie.lifetime),
      cookie("login", "", 0),
    );
  }).pipe(
    Effect.catch((error) =>
      encode(error).pipe(
        Effect.map((response) =>
          // A root-mounted callback must report its error directly to avoid a redirect loop.
          browser.callbackPath === "/"
            ? response
            : HttpServerResponse.redirect(
                `${browser.origin}/?auth_error=${response.status === 503 ? "unavailable" : "login_failed"}`,
                { status: 302 },
              ),
        ),
        Effect.map(cookie("login", "", 0)),
      ),
    ),
  );

  return Layer.mergeAll(
    Http.layer(actions),
    HttpRouter.add("GET", browser.callbackPath, callback),
  ).pipe(
    Layer.provide(
      HttpRouter.middleware((effect) =>
        HttpEffect.appendPreResponseHandler((_request, response) =>
          Effect.succeed(
            HttpServerResponse.setHeaders(response, {
              "cache-control": "no-store",
              "referrer-policy": "no-referrer",
            }),
          ),
        ).pipe(Effect.andThen(effect)),
      ).layer,
    ),
  );
};
