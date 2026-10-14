import { fetchClientMetadataResource as secureFetch } from "@better-auth/cimd/node";
import { Context, Layer } from "effect";
import type { ClientMetadataResourceFetch } from "@better-auth/oauth-provider";

// why: the secure transport cannot abort its DNS lookup, so capacity stays held until it settles
export function createAbortAwareTransport(
  transport: ClientMetadataResourceFetch,
  maximumPending = 8,
): ClientMetadataResourceFetch {
  let pending = 0;

  return (input, init) => {
    const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);

    if (signal?.aborted) return Promise.reject(signal.reason);

    if (pending >= maximumPending)
      return Promise.reject(new Error("CIMD transport capacity reached"));
    pending++;

    return new Promise<Response>((resolve, reject) => {
      let aborted = false;

      const onAbort = () => {
        aborted = true;
        reject(signal?.reason);
      };

      signal?.addEventListener("abort", onAbort, { once: true });

      const release = () => {
        pending--;
        signal?.removeEventListener("abort", onAbort);
      };

      void Promise.resolve()
        .then(() => {
          signal?.throwIfAborted();

          return transport(input, init);
        })
        .then(
          (response) => {
            release();

            if (aborted) {
              void response.body?.cancel().catch(() => {});
            } else resolve(response);
          },
          (cause: unknown) => {
            release();
            reject(cause);
          },
        );
    });
  };
}

export class CimdTransport extends Context.Service<
  CimdTransport,
  { readonly fetch: ClientMetadataResourceFetch }
>()("clankerauth/CimdTransport") {
  static readonly layer = Layer.succeed(CimdTransport, {
    fetch: createAbortAwareTransport(secureFetch),
  });

  static readonly layerWith = (fetch: ClientMetadataResourceFetch | undefined) =>
    fetch === undefined ? CimdTransport.layer : Layer.succeed(CimdTransport, { fetch });
}
