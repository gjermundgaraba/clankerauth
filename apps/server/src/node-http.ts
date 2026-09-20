import { createServer, IncomingMessage, type RequestListener } from "node:http";
import { ByteSize, Effect, Match, Option, Stream, pipe } from "effect";
import {
  Headers,
  HttpBody,
  HttpIncomingMessage,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";

export const createNodeServer = (listener?: RequestListener) =>
  createServer({ requestTimeout: 15000, headersTimeout: 10000 }, listener);

/** Bodies are read through Effect, which enforces this limit on every read by
 * destroying the connection rather than answering.
 */
const maxBodySize = ByteSize.bytes(65536);

interface RequestPolicyOptions {
  readonly baseURL: string;
  /** The direct peer is a trusted reverse proxy: the client is the last X-Forwarded-For hop. */
  readonly trustProxy: boolean;
}

/** Proxy subrequests carry the original request's host and scheme for the return URL. */
const forwardAuthPath = /^\/forward-auth(?:\?|$)/;

/** The address rate limits and session tracking attribute a request to. */
const peerAddress = (
  headers: Headers.Headers,
  remote: Option.Option<string>,
  trustProxy: boolean,
) => {
  const forwarded = headers["x-forwarded-for"]
    ?.split(",")
    .map((hop) => hop.trim())
    .filter(Boolean);

  const last = forwarded?.at(-1);

  return trustProxy && last ? last : Option.getOrElse(remote, () => "unknown");
};

/** Transport policy, not a transport implementation: Effect owns sockets and responses. */
export const requestPolicy =
  ({ baseURL, trustProxy }: RequestPolicyOptions) =>
  <E, R>(handler: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>) =>
    Effect.gen(function* () {
      const incoming = yield* HttpServerRequest.HttpServerRequest;
      const source = incoming.source;
      // Web requests occur only at embedding/test boundaries and already have absolute URLs.
      const target = source instanceof IncomingMessage ? source.url : incoming.url;

      if (!target?.startsWith("/") || target.startsWith("//"))
        return HttpServerResponse.empty({ status: 400 });

      // The configured base URL is the only origin; forwarded headers are never trusted
      // beyond the client address, and only when a proxy is declared. Forward auth is the
      // one route that reads them: it validates the forwarded URL against the cookie domain
      // and never hands those headers to the provider.
      const headers = pipe(
        incoming.headers,
        forwardAuthPath.test(target)
          ? Headers.remove("forwarded")
          : Headers.removeMany(["forwarded", "x-forwarded-host", "x-forwarded-proto"]),
        Headers.set("host", new URL(baseURL).host),
        Headers.set(
          "x-clankerauth-peer",
          peerAddress(incoming.headers, incoming.remoteAddress, trustProxy),
        ),
        Headers.remove("x-forwarded-for"),
      );

      const response = yield* handler.pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, incoming.modify({ headers })),
        Effect.provideService(HttpIncomingMessage.MaxBodySize, maxBodySize),
      );

      // The native Node server ends failed streams cleanly. Preserve failure visibility on
      // the wire without taking over response writing or backpressure from Effect.
      if (!(source instanceof IncomingMessage)) return response;

      return Match.value(response.body).pipe(
        Match.tag("Stream", (body) =>
          HttpServerResponse.setBody(
            response,
            HttpBody.stream(
              body.stream.pipe(Stream.tapCause(() => Effect.sync(() => source.socket.destroy()))),
              body.contentType,
              body.contentLength,
            ),
          ),
        ),
        Match.orElse(() => response),
      );
    }).pipe(Effect.interruptible);
