/**
 * Which callers this app answers at all. Forward auth makes a browser's credential
 * ambient: the proxy attaches an Authorization header to whatever the browser sends,
 * including a cross-site navigation. So the app checks the two headers that say where
 * a request came from, before anything reads the credential.
 *
 * Both checks are raw string comparisons on the headers as sent. Nothing is parsed,
 * so nothing throws and no normalization can widen what is accepted: `notes.example`
 * and `notes.example:443` are different hosts here, as they are to a browser's cookie.
 */
import { Effect } from "effect";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";

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

/**
 * The one path answered without either check. A container probe reaches the app on its
 * bind address and carries neither header, and no application has a second such path.
 */
const probePath = "/healthz";

/** One request, as a Node `upgrade` handler or a router middleware sees it. */
export interface Request {
  /** The request target: `/a?b` or an absolute URL. Only its path is read. */
  readonly target: string;
  readonly host: string | undefined;
  readonly origin: string | undefined;
}

/** The path of a request target. Deliberately not `new URL`: this must not throw. */
const pathOf = (target: string): string => {
  const authority = target.indexOf("://");
  const start = authority === -1 ? 0 : target.indexOf("/", authority + 3);

  if (start === -1) return "/";
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
  const host = options.publicUrl.host;
  const origins = new Set([options.publicUrl.origin, ...(options.allowedOrigins ?? [])]);

  const allows = (request: Request): boolean => {
    if (pathOf(request.target) === probePath) return true;

    // A request with no Host is not a browser request for this app's origin.
    if (request.host !== host) return false;

    return request.origin === undefined || origins.has(request.origin);
  };

  return {
    allows,
    /** Refuse anything `allows` rejects with an empty-bodied 403, before any handler. */
    middleware: HttpRouter.middleware((httpEffect) =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;

        const permitted = allows({
          target: request.originalUrl,
          host: request.headers.host,
          origin: request.headers.origin,
        });

        return permitted ? yield* httpEffect : forbidden;
      }),
    ),
  };
};

export type Policy = ReturnType<typeof make>;
