import { NodeRuntime } from "@effect/platform-node";
import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/http";
import { Otlp, OtlpSerialization } from "effect/observability";

import { nodeHandler } from "./http/application.ts";
import { Settings } from "./issuer/settings.ts";
import { CimdTransport } from "./platform/cimd-transport.ts";
import { listen } from "./platform/node-http.ts";
import { issuerServices } from "./services.ts";

process.umask(0o077);

const telemetry = Otlp.layerFromConfig({
  resource: { serviceName: "clankerauth" },
}).pipe(Layer.provide([FetchHttpClient.layer, OtlpSerialization.layerJson]));

const issuer = issuerServices(Settings.layer, CimdTransport.layer);

const program = Effect.scoped(
  Effect.gen(function* () {
    const settings = yield* Settings;
    const listener = yield* listen(settings.port, settings.host);
    yield* listener.serve(yield* nodeHandler());
    yield* Effect.logInfo("clankerauth ready");

    return yield* Effect.never;
  })
);

NodeRuntime.runMain(
  Effect.provide(program, issuer.pipe(Layer.provideMerge(telemetry)))
);
