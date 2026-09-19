import { createServer, IncomingMessage, type RequestListener } from "node:http";
import { Data, Effect, Inspectable, Match, Option, Result, Stream, pipe } from "effect";
import { NodeStream } from "@effect/platform-node";
import {
  Headers,
  HttpBody,
  HttpClientRequest,
  HttpIncomingMessage,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";

export const createNodeServer = (listener?: RequestListener) =>
  createServer({ requestTimeout: 15000, headersTimeout: 10000 }, listener);

class RequestTooLarge extends Data.TaggedError("RequestTooLarge") {}

/** Transport policy, not a transport implementation: Effect owns sockets and responses. */
export const requestPolicy =
  (baseURL: string) =>
  <E, R>(handler: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>) =>
    Effect.gen(function* () {
      const incoming = yield* HttpServerRequest.HttpServerRequest;
      const source = incoming.source;
      // Web requests occur only at embedding/test boundaries and already have absolute URLs.
      const target = source instanceof IncomingMessage ? source.url : incoming.url;

      if (!target?.startsWith("/") || target.startsWith("//"))
        return HttpServerResponse.empty({ status: 400 });

      const headers = pipe(
        incoming.headers,
        Headers.removeMany([
          "forwarded",
          "x-forwarded-host",
          "x-forwarded-proto",
          "x-clankerauth-peer",
        ]),
        Headers.set("host", new URL(baseURL).host),
        Headers.set(
          "x-clankerauth-peer",
          Option.getOrElse(incoming.remoteAddress, () => "unknown"),
        ),
      );

      // Do not destroy the socket on a size failure: the server still has to send its 413.
      const stream: Stream.Stream<Uint8Array, Error> =
        source instanceof IncomingMessage
          ? NodeStream.fromReadable({ evaluate: () => source, closeOnDone: false })
          : source instanceof Request && source.body === null
            ? Stream.empty
            : incoming.stream;

      const chunks: Uint8Array[] = [];
      let size = 0;

      const collected = yield* Stream.runForEach(stream, (chunk) => {
        size += chunk.byteLength;

        if (size > 65536) return Effect.fail(new RequestTooLarge());
        chunks.push(chunk);

        return Effect.void;
      }).pipe(Effect.result);

      if (Result.isFailure(collected)) {
        return collected.failure instanceof RequestTooLarge
          ? HttpServerResponse.empty({ status: 413, headers: { connection: "close" } })
          : HttpServerResponse.text("Request failed", { status: 400 });
      }

      let request = HttpClientRequest.make(incoming.method)(`${baseURL}${target}`);

      if (incoming.method !== "GET" && incoming.method !== "HEAD")
        request = HttpClientRequest.bodyUint8Array(request, Buffer.concat(chunks));

      // Restore original content type (including its absence) after constructing the body.
      const normalized = new BufferedRequest(
        incoming,
        HttpServerRequest.fromClientRequest(request).modify({
          headers,
          remoteAddress: incoming.remoteAddress,
        }),
      );

      const response = yield* Effect.provideService(
        handler,
        HttpServerRequest.HttpServerRequest,
        normalized,
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

/** Replay bounded bytes while preserving the transport identity used by MCP response hooks. */
class BufferedRequest extends Inspectable.Class implements HttpServerRequest.HttpServerRequest {
  readonly [HttpServerRequest.TypeId] = HttpServerRequest.TypeId;
  readonly [HttpIncomingMessage.TypeId] = HttpIncomingMessage.TypeId;
  readonly original: HttpServerRequest.HttpServerRequest;
  readonly buffered: HttpServerRequest.HttpServerRequest;

  constructor(
    original: HttpServerRequest.HttpServerRequest,
    buffered: HttpServerRequest.HttpServerRequest,
  ) {
    super();
    this.original = original;
    this.buffered = buffered;
  }

  get source() {
    return this.original.source;
  }
  get url() {
    return this.buffered.url;
  }
  get originalUrl() {
    return this.buffered.originalUrl;
  }
  get method() {
    return this.buffered.method;
  }
  get headers() {
    return this.buffered.headers;
  }
  get remoteAddress() {
    return this.buffered.remoteAddress;
  }
  get cookies() {
    return this.buffered.cookies;
  }
  get stream() {
    return this.buffered.stream;
  }
  get arrayBuffer() {
    return this.buffered.arrayBuffer;
  }
  get text() {
    return this.buffered.text;
  }
  get json() {
    return this.buffered.json;
  }
  get urlParamsBody() {
    return this.buffered.urlParamsBody;
  }
  get multipart() {
    return this.buffered.multipart;
  }
  get multipartStream() {
    return this.buffered.multipartStream;
  }
  get upgrade() {
    return this.original.upgrade;
  }
  modify(options: Parameters<HttpServerRequest.HttpServerRequest["modify"]>[0]) {
    return new BufferedRequest(this.original, this.buffered.modify(options));
  }
  toJSON() {
    return this.buffered.toJSON();
  }
}
