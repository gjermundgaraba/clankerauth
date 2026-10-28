import { once } from "node:events";

import { fetchClientMetadataResource as secureFetch } from "@better-auth/cimd/node";
import type { ClientMetadataResourceFetch } from "@better-auth/oauth-provider";
import { Context, Layer } from "effect";
import { constVoid } from "effect/Function";

const abortOf = async (
  signal: AbortSignal,
  until: AbortSignal
): Promise<never> => {
  await once(signal, "abort", { signal: until });

  throw signal.reason;
};

const discard = async (late: Promise<Response>) =>
  await late
    .then(async (response) => await response.body?.cancel())
    .catch(constVoid);

export const createAbortAwareTransport = (
  transport: ClientMetadataResourceFetch,
  maximumPending = 8
): ClientMetadataResourceFetch => {
  let pending = 0;

  const settle = async (
    input: Parameters<ClientMetadataResourceFetch>[0],
    init: Parameters<ClientMetadataResourceFetch>[1],
    signal: AbortSignal | undefined
  ): Promise<Response> => {
    try {
      await Promise.resolve();
      signal?.throwIfAborted();

      return await transport(input, init);
    } finally {
      pending -= 1;
    }
  };

  return async (input, init) => {
    const signal =
      init?.signal ?? (input instanceof Request ? input.signal : undefined);

    if (signal?.aborted === true) {
      throw signal.reason;
    }

    if (pending >= maximumPending) {
      throw new Error("CIMD transport capacity reached");
    }

    pending += 1;

    const work = settle(input, init, signal);

    if (signal === undefined) {
      return await work;
    }

    const listening = new AbortController();

    try {
      return await Promise.race([work, abortOf(signal, listening.signal)]);
    } catch (error) {
      if (signal.aborted) {
        void discard(work);
      }

      throw error;
    } finally {
      listening.abort();
    }
  };
};

export class CimdTransport extends Context.Service<
  CimdTransport,
  { readonly fetch: ClientMetadataResourceFetch }
>()("clankerauth/CimdTransport") {
  static readonly layer = Layer.succeed(CimdTransport, {
    fetch: createAbortAwareTransport(secureFetch),
  });

  static readonly layerWith = (
    fetch: ClientMetadataResourceFetch | undefined
  ) =>
    fetch === undefined
      ? CimdTransport.layer
      : Layer.succeed(CimdTransport, { fetch });
}
