import { Effect } from "effect";
import { application } from "./app.ts";
import { initialize, openAuth } from "./auth.ts";
import { loadSettings } from "./config.ts";
import { createNodeServer, nodeListener } from "./node-http.ts";

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
    const server = createNodeServer(nodeListener(handler, settings.baseURL));
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
