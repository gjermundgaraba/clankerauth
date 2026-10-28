import { Effect } from "effect";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http";

export interface Options {
  /**
   * The origin browsers reach this app at. The application has already validated it;
   * its `host` (with port, when the scheme's default is not used) must equal the Host
   * header, and its `origin` is the one Origin accepted by default.
   */
  readonly publicUrl: URL;
  /**
   * Origins accepted besides the public one, compared exactly. For a desktop shell
   * whose renderer has a private scheme, such as `wtf://app`. No wildcards.
   */
  readonly allowedOrigins?: readonly string[];
}

const uncheckedProbePath = "/healthz";

/** One request, as a Node `upgrade` handler or a router middleware sees it. */
export interface Request {
  /** The request target: `/a?b` or an absolute URL. Only its path is read. */
  readonly target: string;
  readonly host: string | undefined;
  readonly origin: string | undefined;
}

const pathOf = (target: string): string => {
  const authority = target.indexOf("://");
  const start = authority === -1 ? 0 : target.indexOf("/", authority + 3);

  if (start === -1) {
    return "/";
  }

  const rest = target.slice(start);
  const stop = rest.search(/[?#]/u);

  return stop === -1 ? rest : rest.slice(0, stop);
};

const forbidden = HttpServerResponse.text("Forbidden", { status: 403 });

/**
 * Build the policy once, at startup. `allows` is the whole decision and takes no
 * services, so a Node `upgrade` handler applies the same rule as the router.
 */
export const make = (options: Options) => {
  const { host } = options.publicUrl;

  const origins = new Set([
    options.publicUrl.origin,
    ...(options.allowedOrigins ?? []),
  ]);

  const allows = (request: Request): boolean => {
    if (pathOf(request.target) === uncheckedProbePath) {
      return true;
    }

    if (request.host !== host) {
      return false;
    }

    return request.origin === undefined || origins.has(request.origin);
  };

  return {
    allows,
    middleware: HttpRouter.middleware((httpEffect) =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;

        const permitted = allows({
          target: request.originalUrl,
          host: request.headers["host"],
          origin: request.headers["origin"],
        });

        return permitted ? yield* httpEffect : forbidden;
      })
    ),
  };
};

export type Policy = ReturnType<typeof make>;
