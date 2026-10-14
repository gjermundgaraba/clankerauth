import { Effect, Layer, Option } from "effect";
import { HttpRouter, HttpServerRequest } from "effect/http";
import { application } from "../src/http/application.ts";
import type { OpenedIssuer } from "./open-issuer.ts";

/** Test boundary: simulate the socket peer; production never trusts this header. */
export function webApplication(issuer: OpenedIssuer, staticRoot?: string) {
  const { handler, dispose } = HttpRouter.toWebHandler(
    application(staticRoot).pipe(Layer.provide(Layer.succeedContext(issuer.context))),
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
