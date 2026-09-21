/**
 * The deployment edge, for local development: clankerauth's `forward_auth` check and,
 * for upgrades, a reverse proxy. A browser holds no credential of its own; the check
 * trades its forward cookie for a short-lived access token, and this process copies
 * that token upstream, exactly as the Caddy configuration in the README does.
 *
 * It is `node:http` rather than `fetch` because `fetch` overwrites `Sec-Fetch-Mode`,
 * and that header is what tells the issuer whether a request may be redirected through
 * sign-in. Relaying the browser's own header is the whole point of the check.
 */
import { createServer, request as httpRequest } from "node:http";
import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";

/** Paths a caller reaches with its own bearer, or with none at all. */
const defaultPublicPaths = ["/mcp", "/.well-known", "/healthz"] as const;

export interface CheckOptions {
  /** The issuer origin serving `/forward-auth`, under the apps' shared cookie domain. */
  readonly issuer: string;
  /** The origin browsers reach this app at. Its host and scheme are forwarded. */
  readonly appOrigin: string;
  /**
   * The resource identifier to ask for. One resource per app is a string; an app whose
   * surfaces are separate resources passes a function of the request path.
   */
  readonly resource: string | ((path: string) => string);
  /** How long to wait for the issuer. Default 5000 ms. */
  readonly timeoutMs?: number;
}

/** What the issuer decided about one request, including the refusal it wrote. */
export interface Decision {
  readonly status: number;
  readonly authorization: string | undefined;
  readonly location: string | undefined;
  /** The issuer's own response body, relayed verbatim so a refusal reads the same here. */
  readonly body: Buffer;
  readonly contentType: string | undefined;
}

/** The request fields a check reads. A Node `IncomingMessage` already is one. */
export interface CheckedRequest {
  readonly url?: string | undefined;
  readonly headers: IncomingHttpHeaders;
}

/** Whether a resource option selects per request path rather than naming one resource. */
const isPerPath = (resource: CheckOptions["resource"]): resource is (path: string) => string =>
  typeof resource === "function";

const pathOf = (target: string) => {
  const stop = target.search(/[?#]/u);

  return stop === -1 ? target : target.slice(0, stop);
};

const headerValue = (value: string | ReadonlyArray<string> | undefined) =>
  value === undefined ? "" : Array.isArray(value) ? value.join(", ") : String(value);

/**
 * Ask the issuer whether one request may proceed. Rejects instead of deciding when the
 * issuer is unreachable, too slow, or answers `204` without the credential to forward:
 * those are a broken edge, not a refusal to show a browser.
 */
export const check = (options: CheckOptions) => {
  const app = new URL(options.appOrigin);
  const timeout = options.timeoutMs ?? 5000;

  const resourceFor = (path: string) =>
    isPerPath(options.resource) ? options.resource(path) : options.resource;

  return (request: CheckedRequest): Promise<Decision> =>
    new Promise<Decision>((resolve, reject) => {
      const uri = request.url ?? "/";
      const url = new URL("/forward-auth", options.issuer);
      url.searchParams.set("resource", resourceFor(pathOf(uri)));

      const outgoing = httpRequest(
        url,
        {
          headers: {
            cookie: headerValue(request.headers.cookie),
            "sec-fetch-mode": headerValue(request.headers["sec-fetch-mode"]),
            "x-forwarded-proto": app.protocol.slice(0, -1),
            "x-forwarded-host": app.host,
            "x-forwarded-uri": uri,
          },
        },
        (answer) => {
          const status = answer.statusCode ?? 502;
          const { authorization, location } = answer.headers;

          if (status === 204 && authorization === undefined) {
            answer.resume();
            reject(
              new Error("Forward auth answered 204 without an Authorization header to forward"),
            );

            return;
          }

          const chunks: Buffer[] = [];
          answer.on("data", (chunk: Buffer) => chunks.push(chunk));
          answer.on("error", reject);
          answer.on("end", () =>
            resolve({
              status,
              authorization,
              location,
              body: Buffer.concat(chunks),
              contentType: answer.headers["content-type"],
            }),
          );
        },
      );

      outgoing.setTimeout(timeout, () => {
        outgoing.destroy(new Error(`Forward auth did not answer within ${timeout}ms`));
      });
      outgoing.on("error", reject);
      outgoing.end();
    });
};

/** The upgrades this edge owns, and where it proxies them once they are checked. */
export interface SocketOptions {
  /** Where a checked upgrade is proxied, such as `http://127.0.0.1:8080`. */
  readonly backend: string;
  /**
   * Paths whose upgrades this edge owns. Everything else, including a development
   * server's own hot-reload socket, is left untouched.
   */
  readonly paths: readonly string[];
}

export interface EdgeOptions extends CheckOptions {
  /**
   * Path prefixes answered without a check, because their callers bring their own
   * credential or must work without one. Defaults to `/mcp`, `/.well-known`, `/healthz`.
   */
  readonly publicPaths?: readonly string[];
  /** Omit it and every upgrade is left to whoever else listens. */
  readonly sockets?: SocketOptions;
  /** Called with anything this edge swallowed, so a dev server can print it. */
  readonly onError?: (error: Error) => void;
}

const isUnder = (path: string, prefixes: readonly string[]) =>
  prefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));

const toError = (cause: unknown) => (cause instanceof Error ? cause : new Error(String(cause)));

/**
 * Connect-style middleware: an unauthenticated navigation is redirected through the
 * issuer and back, anything else is refused in place, and a request that already
 * carries a credential passes straight through.
 */
export const middleware = (options: EdgeOptions) => {
  const ask = check(options);
  const publicPaths = options.publicPaths ?? [...defaultPublicPaths];

  return (request: CheckedRequest, response: ServerResponse, next: () => void): void => {
    const path = pathOf(request.url ?? "/");

    if (request.headers.authorization !== undefined || isUnder(path, publicPaths)) {
      next();

      return;
    }

    void ask(request).then(
      (decision) => {
        if (decision.status === 204) {
          // Only ever the credential the issuer just minted; `check` rejects a 204 without one.
          request.headers.authorization = decision.authorization;
          next();

          return;
        }

        // The issuer's own refusal, relayed verbatim: a browser reads what it wrote.
        const headers: Record<string, string> = {};

        if (decision.location !== undefined) headers.location = decision.location;

        if (decision.contentType !== undefined) headers["content-type"] = decision.contentType;
        response.writeHead(decision.status, headers);
        response.end(decision.body);
      },
      (cause: unknown) => {
        const error = toError(cause);
        options.onError?.(error);
        response.writeHead(502, { "content-type": "text/plain" });
        response.end(error.message);
      },
    );
  };
};

const copyHeaders = (headers: IncomingHttpHeaders) =>
  Object.fromEntries(
    Object.entries(headers).flatMap(([name, value]) =>
      value === undefined ? [] : [[name, Array.isArray(value) ? value.join(", ") : value]],
    ),
  );

/**
 * Handle one `upgrade`. Returns `false` for a path this edge does not own, so a
 * development server keeps its own hot-reload socket. An upgrade is never a
 * navigation, so an unauthenticated one is refused in place: the page signs in and
 * the client reconnects.
 */
export const upgrade = (options: EdgeOptions) => {
  const ask = check(options);

  return (request: IncomingMessage, socket: Duplex, head: Buffer): boolean => {
    const path = pathOf(request.url ?? "/");
    const sockets = options.sockets;

    if (sockets === undefined || !isUnder(path, sockets.paths)) return false;
    const backend = new URL(sockets.backend);

    const fail = (status: number, reason: string, error?: Error) => {
      if (error) options.onError?.(error);
      // A refusal is a complete HTTP response: end it, do not abort the connection.
      socket.end(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`);
    };

    // A reset on either half is routine for a closing socket; unhandled it takes the
    // whole development server down with it.
    socket.on("error", (error: Error) => {
      options.onError?.(error);
      socket.destroy();
    });

    const proxy = (authorization: string) => {
      const upstream = httpRequest({
        hostname: backend.hostname,
        port: backend.port,
        path: request.url ?? "/",
        // The browser's Host goes upstream unchanged: the app's request policy answers only
        // for its public host, exactly as it does behind a deployment proxy.
        headers: { ...copyHeaders(request.headers), authorization },
      });

      upstream.on("upgrade", (answer, peer, peerHead) => {
        let handshake = "HTTP/1.1 101 Switching Protocols\r\n";

        for (let index = 0; index < answer.rawHeaders.length; index += 2)
          handshake += `${answer.rawHeaders[index]}: ${answer.rawHeaders[index + 1]}\r\n`;
        socket.write(`${handshake}\r\n`);

        if (peerHead.length) socket.write(peerHead);

        if (head.length) peer.write(head);
        // A half closing normally closes the other half the same way; only an error destroys.
        peer.on("error", (error: Error) => {
          options.onError?.(error);
          socket.destroy();
        });
        socket.once("close", () => peer.end());
        peer.once("close", () => socket.end());
        socket.pipe(peer);
        peer.pipe(socket);
      });
      // A backend that answers instead of upgrading refused the socket; relay its status.
      upstream.on("response", (answer: IncomingMessage) => {
        answer.resume();
        fail(answer.statusCode ?? 502, "Upgrade refused");
      });
      upstream.on("error", (cause: Error) => fail(502, "Bad Gateway", cause));
      upstream.end();
    };

    void ask(request).then(
      (decision) => {
        // The client can give up while the issuer is deciding. Opening a backend socket
        // for a connection that is already gone would leak both halves of the handshake.
        if (socket.destroyed) return;

        if (decision.status !== 204 || decision.authorization === undefined) {
          fail(401, "Unauthorized");

          return;
        }

        proxy(decision.authorization);
      },
      (cause: unknown) => {
        if (!socket.destroyed) fail(502, "Bad Gateway", toError(cause));
      },
    );

    return true;
  };
};

/** Install both halves on a plain Node server, for an edge that is not a Vite plugin. */
export const attach = (server: Server, options: EdgeOptions) => {
  const handle = middleware(options);
  const take = upgrade(options);

  server.on("upgrade", (request: IncomingMessage, socket: Duplex, head: Buffer) => {
    take(request, socket, head);
  });

  return handle;
};

/** The development server this plugin attaches to. Structural, so Vite is never imported. */
export interface DevServerLike {
  readonly middlewares: {
    use(
      handler: (request: IncomingMessage, response: ServerResponse, next: () => void) => void,
    ): void;
  };
  readonly httpServer?:
    | {
        on(
          event: "upgrade",
          listener: (request: IncomingMessage, socket: Duplex, head: Buffer) => void,
        ): void;
      }
    | null
    | undefined;
}

/**
 * A Vite plugin applying the same edge. Nothing here imports Vite: the object is
 * structurally what Vite accepts, so this package never puts Vite in a consumer's
 * dependency graph or its type graph.
 */
export const forwardAuth = (options: EdgeOptions) => {
  const handle = middleware(options);
  const take = upgrade(options);

  return {
    name: "clankerauth-forward-auth",
    apply: "serve" as const,
    configureServer: (server: DevServerLike) => {
      server.middlewares.use(handle);
      // Vite's proxy claims `upgrade` before an asynchronous decision can be made, so
      // this listener runs first and returns the sockets it does not own.
      server.httpServer?.on("upgrade", (request, socket, head) => {
        take(request, socket, head);
      });
    },
  };
};

/** Claim a free loopback port before anything that must know its own origin up front. */
export const reserveLoopbackPort = async (): Promise<number> => {
  const reservation = createServer();
  await new Promise<void>((done) => reservation.listen(0, "127.0.0.1", done));
  const address = reservation.address();

  if (!(address instanceof Object)) throw new Error("Could not reserve a loopback port");
  await new Promise<void>((done, reject) =>
    reservation.close((error) => (error ? reject(error) : done())),
  );

  return address.port;
};
