import { Context, Effect } from "effect";
import { Cookies, HttpRouter, HttpServerResponse } from "effect/unstable/http";

/** Set-Cookie values an action attaches to its own HTTP response. */
export class ResponseCookies extends Context.Service<
  ResponseCookies,
  { readonly add: (setCookie: Iterable<string>) => Effect.Effect<void> }
>()("clankerauth/ResponseCookies") {}

/** Per request: collect cookies while the action runs, then attach them to its response. */
export const responseCookies = HttpRouter.middleware<{ provides: ResponseCookies }>()((handler) =>
  Effect.gen(function* () {
    const pending: string[] = [];

    const response = yield* Effect.provideService(handler, ResponseCookies, {
      add: (values) => Effect.sync(() => pending.push(...values)),
    });

    return pending.length
      ? HttpServerResponse.mergeCookies(response, Cookies.fromSetCookie(pending))
      : response;
  }),
);
