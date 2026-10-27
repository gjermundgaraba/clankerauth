import { Effect } from "effect";
import { Cookies, HttpRouter, HttpServerResponse } from "effect/http";

import { ResponseCookies } from "../owner/setup.ts";

export const responseCookies = HttpRouter.middleware<{
  provides: ResponseCookies;
}>()((handler) =>
  Effect.gen(function* () {
    const pending: string[] = [];

    const response = yield* Effect.provideService(handler, ResponseCookies, {
      add: (values) => Effect.sync(() => pending.push(...values)),
    });

    return pending.length
      ? HttpServerResponse.mergeCookies(
          response,
          Cookies.fromSetCookie(pending)
        )
      : response;
  })
);
