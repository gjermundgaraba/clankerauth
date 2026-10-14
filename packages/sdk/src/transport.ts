import { Context, Effect } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";
import { ProviderUnavailable } from "./errors.ts";

export const execute = (
  client: HttpClient.HttpClient,
  request: HttpClientRequest.HttpClientRequest,
) =>
  Effect.contextWith((context: Context.Context<never>) =>
    HttpClient.withScope(client)
      .execute(request)
      .pipe(
        Effect.provideService(FetchHttpClient.RequestInit, {
          ...Context.getOrUndefined(context, FetchHttpClient.RequestInit),
          redirect: "error",
        }),
        Effect.mapError((cause) => new ProviderUnavailable({ operation: "http.request", cause })),
      ),
  );
