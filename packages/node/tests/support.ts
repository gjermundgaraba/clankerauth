import { Cause, Effect, Exit, Schema } from "effect";
import { FetchHttpClient, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import { BrowserHttp, SessionStore } from "../src/index.ts";
import type { BrowserSession } from "../src/browser.ts";

export const LoginResponse = Schema.Struct({ url: Schema.String });

export const run = async <A, E>(effect: Effect.Effect<A, E>) => {
  const exit = await Effect.runPromiseExit(effect);

  if (Exit.isFailure(exit)) throw Cause.squash(exit.cause);

  return exit.value;
};

export const withHttp = <A, E>(
  effect: Effect.Effect<A, E, import("effect/unstable/http/HttpClient").HttpClient>,
) => effect.pipe(Effect.provide(FetchHttpClient.layer));

export const memoryStore = () => {
  const rows = new Map<string, { payload: string; expires: number }>();

  const store = SessionStore.of({
    get: (id) => Effect.sync(() => rows.get(id)),
    put: (id, payload, expires) =>
      Effect.sync(() => {
        rows.set(id, { payload, expires });
      }),
    delete: (id) =>
      Effect.sync(() => {
        rows.delete(id);
      }),
    sweep: (now) =>
      Effect.sync(() => {
        for (const [id, row] of rows) if (row.expires <= now) rows.delete(id);
      }),
  });

  return { store, rows };
};

/** Test-only Web boundary, exercising the actual Effect HTTP handlers. */
export const webBrowser = (browser: BrowserSession) => {
  const handlers = BrowserHttp.handlers(browser);

  const route = (handler: typeof handlers.login) => (request: Request) =>
    run(
      handler.pipe(
        Effect.provideService(
          HttpServerRequest.HttpServerRequest,
          HttpServerRequest.fromWeb(request),
        ),
        Effect.map(HttpServerResponse.toWeb),
      ),
    );

  const raw = (request: Request) =>
    HttpServerRequest.fromWeb(request).cookies[`${browser.cookie.name}_session`];

  return {
    native: browser,
    login: route(handlers.login),
    callback: route(handlers.callback),
    session: route(handlers.session),
    logout: route(handlers.logout),
    accessToken: (request: Request) => run(browser.accessToken(raw(request))),
  };
};
