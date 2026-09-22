import { Effect, Layer, Option } from "effect";
import { HttpRouter, HttpServerRequest } from "effect/unstable/http";
import { application } from "../src/app.ts";
import { Auth } from "../src/auth.ts";

/** Test boundary: simulate the socket peer; production never trusts this header. */
export function webApplication(service: Auth["Service"], staticRoot?: string) {
  const { handler, dispose } = HttpRouter.toWebHandler(
    application(staticRoot).pipe(Layer.provide(Layer.succeed(Auth, service))),
    {
      disableLogger: true,
      middleware: (effect) =>
        Effect.flatMap(HttpServerRequest.HttpServerRequest, (request) =>
          Effect.provideService(
            effect,
            HttpServerRequest.HttpServerRequest,
            request.modify({
              remoteAddress: Option.fromNullishOr(request.headers["x-clankerauth-peer"]),
            }),
          ),
        ),
    },
  );

  return Object.assign(handler, { dispose });
}
