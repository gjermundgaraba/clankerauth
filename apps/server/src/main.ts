import { Effect, Layer } from "effect";
import { NodeHttpServer, NodeRuntime } from "@effect/platform-node";
import { FetchHttpClient, HttpRouter } from "effect/unstable/http";
import { Otlp, OtlpSerialization } from "effect/unstable/observability";
import { application } from "./app.ts";
import { Auth } from "./auth.ts";
import { loadSettings } from "./config.ts";
import { createNodeServer } from "./node-http.ts";

process.umask(0o077);

/** Standard `OTEL_*` configuration: spans, metrics and logs go to a collector only when one is set. */
const telemetry = Otlp.layerFromConfig({ resource: { serviceName: "clankerauth" } }).pipe(
  Layer.provide([FetchHttpClient.layer, OtlpSerialization.layerJson]),
);

/** The configured issuer for this process; its scope outlives every request scope. */
const issuer = Layer.unwrap(Effect.map(loadSettings, (settings) => Auth.layer(settings)));

const program = Effect.scoped(
  Effect.gen(function* () {
    const { settings } = yield* Auth;
    const nodeServer = createNodeServer();

    const server = yield* NodeHttpServer.make(() => nodeServer, {
      port: settings.port,
      host: settings.host,
      // Request scopes interrupt immediately rather than waiting for response delivery.
      disablePreemptiveShutdown: true,
    });

    const handler = yield* HttpRouter.toHttpEffect(application());
    yield* server.serve(handler);
    // Stop admission first, without waiting for open responses before interrupting them.
    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        nodeServer.close();
        nodeServer.closeAllConnections();
      }),
    );
    yield* Effect.logInfo("clankerauth ready");
    yield* Effect.never;
  }),
);

// The collector outlives the issuer, so migration and shutdown spans still reach it.
NodeRuntime.runMain(Effect.provide(program, issuer.pipe(Layer.provideMerge(telemetry))));
