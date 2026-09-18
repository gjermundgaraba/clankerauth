import { Duration, Effect, Layer, Schema, SchemaAST, Stream } from "effect";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import { transactionLifetime, type BrowserSession } from "./browser.ts";
import { authenticationErrors, InvalidRequest, RequestTooLarge } from "./errors.ts";

const LoginInput = Schema.Struct({ returnTo: Schema.String });

const errors = [...authenticationErrors, InvalidRequest, RequestTooLarge] as const;

const encodeError = HttpServerResponse.schemaJson(Schema.Union(errors));

const responses = errors.map((schema) => ({
  matches: Schema.is(schema),
  status: SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500,
}));

/** Browser transport owns origin checks, bounded input, cookies, redirects and error serialization. */
export const handlers = (browser: BrowserSession) => {
  const sessionName = `${browser.cookie.name}_session`;
  const transactionName = `${browser.cookie.name}_login`;

  const cookie = (name: string, value: string, age: number) =>
    HttpServerResponse.setCookieUnsafe(name, value, {
      path: "/",
      httpOnly: true,
      sameSite: "lax",
      secure: browser.cookie.secure,
      maxAge: Duration.seconds(age),
    });

  const current = Effect.map(
    HttpServerRequest.HttpServerRequest,
    (request) => request.cookies[sessionName],
  );

  const mutation = Effect.flatMap(HttpServerRequest.HttpServerRequest, (request) =>
    browser.checkOrigin(request.headers.origin),
  );

  const respond = <
    A extends HttpServerResponse.HttpServerResponse,
    E extends (typeof errors)[number]["Type"],
    R,
  >(
    action: Effect.Effect<A, E, R>,
    callback = false,
  ) =>
    action.pipe(
      Effect.catch((error) => {
        const matched = responses.find((response) => response.matches(error));

        if (!matched) return Effect.die(new Error("Undeclared browser-session error"));
        const { status } = matched;

        // A root-mounted callback must report its error directly to avoid a redirect loop.
        const response =
          callback && browser.callbackPath !== "/"
            ? Effect.succeed(
                HttpServerResponse.redirect(
                  `${browser.origin}/?auth_error=${status === 503 ? "unavailable" : "login_failed"}`,
                  { status: 302 },
                ),
              )
            : encodeError(error, { status }).pipe(Effect.orDie);

        return callback ? response.pipe(Effect.map(cookie(transactionName, "", 0))) : response;
      }),
      Effect.map((response) =>
        response.pipe(
          HttpServerResponse.setHeader("referrer-policy", "no-referrer"),
          HttpServerResponse.setHeader("cache-control", "no-store"),
        ),
      ),
    );

  return {
    login: respond(
      Effect.gen(function* () {
        yield* mutation;
        const request = yield* HttpServerRequest.HttpServerRequest;
        let size = 0;
        const chunks: Uint8Array[] = [];
        yield* Stream.runForEach(request.stream, (chunk) => {
          size += chunk.byteLength;

          if (size > 16 * 1024)
            return Effect.fail(new RequestTooLarge({ message: "Login request too large" }));
          chunks.push(chunk);

          return Effect.void;
        }).pipe(
          Effect.mapError((error) =>
            error instanceof RequestTooLarge
              ? error
              : new InvalidRequest({ message: "Invalid login request" }),
          ),
        );

        const input = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(LoginInput))(
          Buffer.concat(chunks).toString("utf8"),
        ).pipe(Effect.mapError(() => new InvalidRequest({ message: "Invalid login request" })));

        const result = yield* browser.login(input.returnTo);

        return HttpServerResponse.jsonUnsafe({ url: result.url }).pipe(
          cookie(transactionName, result.transaction, transactionLifetime),
        );
      }),
    ),
    callback: respond(
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;

        const url = yield* Effect.try({
          try: () => new URL(request.originalUrl, browser.origin),
          catch: () => new InvalidRequest({ message: "Invalid callback URL" }),
        });

        const result = yield* browser.callback(url, request.cookies[transactionName]);

        return HttpServerResponse.redirect(result.location, { status: 302 }).pipe(
          cookie(sessionName, result.session, browser.cookie.lifetime),
          cookie(transactionName, "", 0),
        );
      }),
      true,
    ),
    session: respond(
      Effect.gen(function* () {
        return HttpServerResponse.jsonUnsafe(yield* browser.session(yield* current));
      }),
    ),
    logout: respond(
      Effect.gen(function* () {
        yield* mutation;
        yield* browser.logout(yield* current);

        return HttpServerResponse.empty({ status: 204 }).pipe(cookie(sessionName, "", 0));
      }),
    ),
  };
};

export const layer = (browser: BrowserSession) => {
  const routes = handlers(browser);

  return Layer.mergeAll(
    HttpRouter.add("POST", "/auth/login", routes.login),
    HttpRouter.add("GET", browser.callbackPath, routes.callback),
    HttpRouter.add("GET", "/auth/session", routes.session),
    HttpRouter.add("POST", "/auth/logout", routes.logout),
  );
};
