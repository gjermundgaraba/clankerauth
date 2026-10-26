import { createServer, IncomingMessage, type RequestListener } from "node:http";
import { ByteSize, Effect, Option, type Scope, pipe } from "effect";
import { Headers, HttpIncomingMessage, HttpServerRequest, HttpServerResponse } from "effect/http";

export const peerHeader = "x-clankerauth-peer";

export const createNodeServer = (listener?: RequestListener) =>
  createServer({ requestTimeout: 15000, headersTimeout: 10000 }, listener);

export interface Listener {
  readonly port: number;
  /** Answers with `handler`, 503 until then. Closing the calling scope stops listening first. */
  readonly serve: (handler: RequestListener) => Effect.Effect<void, never, Scope.Scope>;
}

const unavailable: RequestListener = (_incoming, outgoing) => {
  outgoing.writeHead(503).end();
};

export const listen = Effect.fn("NodeHttp.listen")(function* (
  port: number,
  host?: string,
): Effect.fn.Return<Listener, Error, Scope.Scope> {
  let handler = unavailable;
  const server = createNodeServer((incoming, outgoing) => handler(incoming, outgoing));

  // why: stop admitting connections first, then interrupt open responses without waiting
  const stop = Effect.callback<void>((resume) => {
    server.close(() => resume(Effect.void));
    server.closeAllConnections();
  });

  yield* Effect.acquireRelease(
    Effect.callback<void, Error>((resume) => {
      const failed = (error: Error) => resume(Effect.fail(error));
      server.once("error", failed);
      server.listen(port, host, () => {
        server.off("error", failed);
        resume(Effect.void);
      });
    }),
    () => stop,
  );

  const address = server.address();

  if (!(address instanceof Object)) return yield* Effect.die(new Error("Expected a TCP listener"));

  return {
    port: address.port,
    serve: (next) =>
      Effect.addFinalizer(() => stop).pipe(Effect.tap(() => Effect.sync(() => (handler = next)))),
  };
});

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

      return yield* handler.pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, incoming.modify({ headers })),
        Effect.provideService(HttpIncomingMessage.MaxBodySize, maxBodySize),
      );
    }).pipe(Effect.interruptible);
