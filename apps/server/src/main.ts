import { createServer } from "node:http";
import { Effect } from "effect";
import { application } from "./app.ts";
import { initialize, openAuth } from "./auth.ts";
import { loadSettings } from "./config.ts";

process.umask(0o077);
const program = Effect.scoped(
  Effect.gen(function* () {
    const settings = yield* loadSettings;
    const service = yield* Effect.acquireRelease(
      Effect.tryPromise(() => openAuth(settings)),
      (s) => Effect.promise(() => s.close()),
    );
    yield* Effect.tryPromise(() => initialize(service));
    const handler = yield* Effect.acquireRelease(
      Effect.sync(() => application(service)),
      (app) => Effect.promise(() => app.dispose()),
    );
    const server = createServer(async (incoming, outgoing) => {
      try {
        if (!incoming.url?.startsWith("/") || incoming.url.startsWith("//")) {
          outgoing.writeHead(400).end();
          return;
        }
        const headers = new Headers();
        for (const [key, value] of Object.entries(incoming.headers)) {
          if (
            value &&
            !["forwarded", "x-forwarded-host", "x-forwarded-proto", "x-clankerauth-peer"].includes(
              key,
            )
          )
            headers.set(key, Array.isArray(value) ? value.join(", ") : value);
        }
        // Rate limits use the direct socket peer. The proxy must enforce per-user/IP limits too.
        headers.set("x-clankerauth-peer", incoming.socket.remoteAddress ?? "unknown");
        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of incoming) {
          size += chunk.length;
          if (size > 65536) {
            outgoing.writeHead(413).end();
            return;
          }
          chunks.push(chunk);
        }
        const req = new Request(`${settings.baseURL}${incoming.url}`, {
          method: incoming.method,
          headers,
          body:
            incoming.method === "GET" || incoming.method === "HEAD"
              ? undefined
              : Buffer.concat(chunks),
        });
        const response = await handler(req);
        outgoing.writeHead(response.status, {
          ...Object.fromEntries(response.headers),
          "set-cookie": response.headers.getSetCookie(),
        });
        outgoing.end(Buffer.from(await response.arrayBuffer()));
      } catch {
        outgoing.writeHead(500).end("Request failed");
      }
    });
    server.requestTimeout = 15000;
    server.headersTimeout = 10000;
    yield* Effect.acquireRelease(
      Effect.tryPromise(
        () =>
          new Promise<void>((resolve, reject) => {
            server.once("error", reject);
            server.listen(settings.port, settings.host, resolve);
          }),
      ),
      () =>
        Effect.promise(
          () =>
            new Promise<void>((resolve) => {
              server.close(() => resolve());
              server.closeIdleConnections();
            }),
        ),
    );
    console.log("Clanker Auth ready");
    yield* Effect.promise(
      () =>
        new Promise<void>((resolve) => {
          process.once("SIGTERM", resolve);
          process.once("SIGINT", resolve);
        }),
    );
  }),
);
await Effect.runPromise(program).catch(() => {
  console.error("Startup failed. Check configuration, database schema and owner state.");
  process.exitCode = 1;
});
