import { fetchClientMetadataResource as secureFetch } from "@better-auth/cimd/node";
import type { ClientMetadataResourceFetch } from "@better-auth/oauth-provider";

// The secure Node transport pins validated DNS answers, but its initial DNS
// lookup cannot be aborted. Release the service's execution lane on cancellation
// while retaining capacity for every underlying operation until it settles.
export function createAbortAwareTransport(
  transport: ClientMetadataResourceFetch,
  maximumPending = 8,
): ClientMetadataResourceFetch {
  if (!Number.isSafeInteger(maximumPending) || maximumPending < 1)
    throw new RangeError("maximumPending must be a positive safe integer");
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
              // A transport may finish after the caller has gone away. Dispose
              // of its body and consume cancellation errors without an orphaned
              // rejection. No provider/database work runs in this continuation.
              void response.body?.cancel().catch(() => {});
            } else resolve(response);
          },
          (error: unknown) => {
            release();
            reject(error);
          },
        );
    });
  };
}

export const fetchClientMetadataResource = createAbortAwareTransport(secureFetch);
