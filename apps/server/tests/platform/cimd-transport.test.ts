import type { ClientMetadataResourceFetch } from "@better-auth/oauth-provider";
import { it } from "@effect/vitest";
import { Effect } from "effect";
import { describe, expect, vi } from "vite-plus/test";

import {
  CimdTransport,
  createAbortAwareTransport,
} from "../../src/platform/cimd-transport.ts";

const rejection = (url: string) =>
  Effect.gen(function* () {
    const { fetch } = yield* CimdTransport;

    return yield* Effect.flip(
      Effect.tryPromise({
        try: async () => await fetch(url),
        catch: (cause) =>
          cause instanceof Error ? cause.message : String(cause),
      })
    );
  }).pipe(Effect.provide(CimdTransport.layer));

const url = "https://client.example/metadata.json";

describe("abort-aware CIMD transport", () => {
  it("aborts stalled DNS while keeping its capacity occupied until settlement", async () => {
    const stalled = Promise.withResolvers<Response>();

    const transport = vi.fn<ClientMetadataResourceFetch>(
      async () => await stalled.promise
    );

    const fetch = createAbortAwareTransport(transport, 1);
    const controller = new AbortController();
    const result = fetch(url, { signal: controller.signal });
    await Promise.resolve();
    expect(transport).toHaveBeenCalledOnce();
    const failure = new Error("metadata timeout");
    controller.abort(failure);
    await expect(result).rejects.toBe(failure);
    await expect(fetch(url)).rejects.toThrow("capacity reached");
    expect(transport).toHaveBeenCalledOnce();

    const cancel = vi.fn<() => void>();
    const body = new ReadableStream({ cancel });
    stalled.resolve(new Response(body));
    await vi.waitFor(() => {
      expect(cancel).toHaveBeenCalledOnce();
    });
    transport.mockResolvedValue(new Response("recovered"));
    const recovered = await fetch(url);
    await expect(recovered.text()).resolves.toBe("recovered");
  });

  it("consumes late transport failure and releases capacity", async () => {
    const stalled = Promise.withResolvers<Response>();

    const transport = vi.fn<ClientMetadataResourceFetch>(
      async () => await stalled.promise
    );

    const fetch = createAbortAwareTransport(transport, 1);
    const controller = new AbortController();
    const result = fetch(url, { signal: controller.signal });
    await Promise.resolve();

    controller.abort();
    await expect(result).rejects.toMatchObject({
      name: "AbortError",
    });
    stalled.reject(new Error("DNS eventually failed"));
    await stalled.promise.catch(() => {});
    // why: the wrapper releases capacity in a continuation one microtask after settlement
    await Promise.resolve();
    transport.mockResolvedValue(new Response("recovered"));
    const recovered = await fetch(url);
    await expect(recovered.text()).resolves.toBe("recovered");
  });

  it("already-aborted requests never invoke transport or consume capacity", async () => {
    const transport = vi.fn<ClientMetadataResourceFetch>(
      () => new Response("ok")
    );

    const fetch = createAbortAwareTransport(transport, 1);
    const controller = new AbortController();
    controller.abort();
    await expect(
      fetch(new Request(url, { signal: controller.signal }))
    ).rejects.toMatchObject({
      name: "AbortError",
    });
    expect(transport).not.toHaveBeenCalled();
    const passed = await fetch(url);
    await expect(passed.text()).resolves.toBe("ok");
  });

  it("passes through requests and responses and handles synchronous failures", async () => {
    const response = new Response("metadata");
    const transport = vi.fn<ClientMetadataResourceFetch>(() => response);
    const fetch = createAbortAwareTransport(transport, 1);
    const init = { headers: { Accept: "application/json" } };
    await expect(fetch(url, init)).resolves.toBe(response);
    expect(transport).toHaveBeenCalledWith(url, init);
    transport.mockImplementationOnce(() => {
      throw new Error("bad transport input");
    });
    await expect(fetch(url)).rejects.toThrow("bad transport input");
    await expect(fetch(url)).resolves.toBe(response);
  });
});

describe("production CIMD transport", () => {
  it.live.each([
    "https://127.0.0.1/metadata.json",
    "https://10.0.0.1/metadata.json",
  ])("rejects private metadata address %s", (metadata) =>
    Effect.gen(function* () {
      expect(yield* rejection(metadata)).toContain("public-routable");
    })
  );
  it.live("rejects non-HTTPS metadata", () =>
    Effect.gen(function* () {
      expect(yield* rejection("http://127.0.0.1/metadata.json")).toContain(
        "HTTPS"
      );
    })
  );
});
