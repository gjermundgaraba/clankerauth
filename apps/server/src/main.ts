import { Effect } from "effect";
import { NodeHttpServer, NodeRuntime } from "@effect/platform-node";
import { HttpRouter } from "effect/unstable/http";
import { application } from "./app.ts";
import { initialize, openAuth } from "./auth.ts";
import { loadSettings } from "./config.ts";
import { createNodeServer } from "./node-http.ts";

process.umask(0o077);

const program = Effect.scoped(
  Effect.gen(function* () {
    const settings = yield* loadSettings;

    const service = yield* Effect.acquireRelease(
      Effect.tryPromise(() => openAuth(settings)),
      (s) => Effect.promise(() => s.close()),
    );

    // Provider migrations cannot be cancelled; settle before database finalization.
    yield* Effect.tryPromise(() => initialize(service)).pipe(Effect.uninterruptible);

    const nodeServer = createNodeServer();

    const server = yield* NodeHttpServer.make(() => nodeServer, {
      port: settings.port,
      host: settings.host,
      // Request scopes interrupt immediately rather than waiting for response delivery.
      disablePreemptiveShutdown: true,
    });

    const handler = yield* HttpRouter.toHttpEffect(application(service));
    yield* server.serve(handler);
    // Stop admission first, without waiting for open responses before interrupting them.
    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        nodeServer.close();
        nodeServer.closeAllConnections();
      }),
    );
    yield* Effect.logInfo("Clanker Auth ready");
    yield* Effect.never;
  }),
);

NodeRuntime.runMain(program);
