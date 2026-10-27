import { Context, Effect } from "effect";
import type { HttpClientRequest } from "effect/http";
import { FetchHttpClient, HttpClient } from "effect/http";

import { ProviderUnavailable } from "./errors.ts";

/**
 * Send `request` without following a redirect: a redirect fails the read. `manual`, since
 * Cloudflare Workers rejects `redirect: "error"` before sending.
 */
export const execute = (
  client: HttpClient.HttpClient,
  request: HttpClientRequest.HttpClientRequest
) =>
  Effect.contextWith((context: Context.Context<never>) =>
    HttpClient.withScope(client)
      .execute(request)
      .pipe(
        Effect.provideService(FetchHttpClient.RequestInit, {
          ...Context.getOrUndefined(context, FetchHttpClient.RequestInit),
          redirect: "manual",
        }),
        Effect.mapError(
          (cause) =>
            new ProviderUnavailable({ operation: "http.request", cause })
        ),
        Effect.filterOrFail(
          (response) => response.status < 300 || response.status >= 400,
          (response) =>
            new ProviderUnavailable({
              operation: "http.redirect",
              cause: { status: response.status },
            })
        )
      )
  );
