import { Effect } from "effect";
import { FetchHttpClient } from "effect/unstable/http";

export const withHttp = <A, E>(
  effect: Effect.Effect<A, E, import("effect/unstable/http/HttpClient").HttpClient>,
) => effect.pipe(Effect.provide(FetchHttpClient.layer));
