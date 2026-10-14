import { Effect, Layer } from "effect";
import { NodeHttpServer, NodeRuntime } from "@effect/platform-node";
import { FetchHttpClient, HttpRouter } from "effect/http";
import { Otlp, OtlpSerialization } from "effect/observability";
import { application } from "./http/application.ts";
import { Settings } from "./issuer/settings.ts";
import { CimdTransport } from "./platform/cimd-transport.ts";
import { issuerServices } from "./services.ts";
import { createNodeServer } from "./platform/node-http.ts";

process.umask(0o077);

const telemetry = Otlp.layerFromConfig({ resource: { serviceName: "clankerauth" } }).pipe(
  Layer.provide([FetchHttpClient.layer, OtlpSerialization.layerJson]),
);

const issuer = issuerServices(Settings.layer, CimdTransport.layer);

const program = Effect.scoped(
  Effect.gen(function* () {
    const settings = yield* Settings;
    const nodeServer = createNodeServer();

    const server = yield* NodeHttpServer.make(() => nodeServer, {
      port: settings.port,
      host: settings.host,
      // why: shutdown interrupts request scopes at once instead of waiting to deliver responses
      disablePreemptiveShutdown: true,
    });

    const handler = yield* HttpRouter.toHttpEffect(application());
    yield* server.serve(handler);
    // why: stop admitting connections first, then interrupt open responses without waiting
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

// why: the collector outlives the issuer, so migration and shutdown spans still reach it
NodeRuntime.runMain(Effect.provide(program, issuer.pipe(Layer.provideMerge(telemetry))));
