import { Cause, Context, Effect, Exit } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/unstable/http";
import type { HttpClientError } from "effect/unstable/http/HttpClientError";
import { ProviderUnavailable } from "./errors.ts";

/** Preserve Effect causes while crossing the foreign library's Promise callback boundary. */
export class TransportFailure extends Error {
  readonly effectCause: Cause.Cause<ProviderUnavailable | HttpClientError>;
  constructor(effectCause: Cause.Cause<ProviderUnavailable | HttpClientError>) {
    super("Protocol transport failed");
    this.effectCause = effectCause;
  }
}

/**
 * The only Effect -> Promise bridge: the third-party OAuth library requires Fetch.
 * Capture the calling fiber's context per invocation, and propagate its AbortSignal.
 * Buffer small protocol responses so no response resource outlives the adapter effect.
 */
export const protocolTransport = Effect.fn("Auth.protocolTransport")(function* () {
  const client = yield* HttpClient.HttpClient;
  const context = yield* Effect.context<never>();

  return (url: string, init: RequestInit): Promise<Response> =>
    Effect.runPromiseExitWith(context)(
      Effect.gen(function* () {
        const request = yield* Effect.try({
          try: () => HttpClientRequest.fromWeb(new Request(url, init)),
          catch: (cause) => new ProviderUnavailable({ operation: "request", cause }),
        });

        const response = yield* execute(client, request);

        if (response.status >= 300 && response.status < 400)
          return yield* new ProviderUnavailable({
            operation: "redirect",
            cause: { status: response.status },
          });
        const body = yield* response.arrayBuffer;

        return new Response(
          response.status === 204 || response.status === 205 || response.status === 304
            ? null
            : body,
          {
            status: response.status,
            headers: response.headers,
          },
        );
      }).pipe(Effect.scoped),
      { signal: init.signal ?? undefined },
    ).then((exit) => {
      if (Exit.isFailure(exit)) throw new TransportFailure(exit.cause);

      return exit.value;
    });
});

// Node transports do not follow redirects by default. Also pin FetchHttpClient's policy;
// forwarding credentials through a redirect is not an authentication fallback.
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
