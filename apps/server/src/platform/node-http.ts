import { createServer, IncomingMessage, type RequestListener } from "node:http";
import { ByteSize, Effect, Match, Option, Stream, pipe } from "effect";
import {
  Headers,
  HttpBody,
  HttpIncomingMessage,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/http";

export const peerHeader = "x-clankerauth-peer";

export const createNodeServer = (listener?: RequestListener) =>
  createServer({ requestTimeout: 15000, headersTimeout: 10000 }, listener);

const maxBodySize = ByteSize.bytes(65536);

interface RequestPolicyOptions {
  readonly baseURL: string;
  /** The direct peer is a trusted reverse proxy: the client is the last X-Forwarded-For hop. */
  readonly trustProxy: boolean;
}

const forwardAuthPath = /^\/forward-auth(?:\?|$)/;

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

export const requestPolicy =
  ({ baseURL, trustProxy }: RequestPolicyOptions) =>
  <E, R>(handler: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>) =>
    Effect.gen(function* () {
      const incoming = yield* HttpServerRequest.HttpServerRequest;
      const source = incoming.source;
      const target = source instanceof IncomingMessage ? source.url : incoming.url;

      if (!target?.startsWith("/") || target.startsWith("//"))
        return HttpServerResponse.empty({ status: 400 });

      const headers = pipe(
        incoming.headers,
        forwardAuthPath.test(target)
          ? Headers.remove("forwarded")
          : Headers.removeMany(["forwarded", "x-forwarded-host", "x-forwarded-proto"]),
        Headers.set("host", new URL(baseURL).host),
        Headers.set(peerHeader, peerAddress(incoming.headers, incoming.remoteAddress, trustProxy)),
        Headers.remove("x-forwarded-for"),
      );

      const response = yield* handler.pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, incoming.modify({ headers })),
        Effect.provideService(HttpIncomingMessage.MaxBodySize, maxBodySize),
      );

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
