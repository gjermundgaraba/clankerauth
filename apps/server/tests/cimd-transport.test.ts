import { describe, expect, test, vi } from "vite-plus/test";
import { createAbortAwareTransport } from "../src/cimd-transport.ts";

const url = "https://client.example/metadata.json";

describe("abort-aware CIMD transport", () => {
  test("aborts stalled DNS while keeping its capacity occupied until settlement", async () => {
    const stalled = Promise.withResolvers<Response>();
    const transport = vi.fn(() => stalled.promise);
    const fetch = createAbortAwareTransport(transport, 1);
    const controller = new AbortController();
    const result = fetch(url, { signal: controller.signal });
    await Promise.resolve();
    expect(transport).toHaveBeenCalledTimes(1);
    const failure = new Error("metadata timeout");
    const rejection = expect(result).rejects.toBe(failure);
    controller.abort(failure);
    await rejection;
    await expect(fetch(url)).rejects.toThrow("capacity reached");
    expect(transport).toHaveBeenCalledTimes(1);

    const cancel = vi.fn();
    const body = new ReadableStream({ cancel });
    stalled.resolve(new Response(body));
    await vi.waitFor(() => expect(cancel).toHaveBeenCalledTimes(1));
    transport.mockImplementation(() => Promise.resolve(new Response("recovered")));
    expect(await (await fetch(url)).text()).toBe("recovered");
  });

  test("consumes late transport failure and releases capacity", async () => {
    const stalled = Promise.withResolvers<Response>();
    const transport = vi.fn(() => stalled.promise);
    const fetch = createAbortAwareTransport(transport, 1);
    const controller = new AbortController();
    const result = fetch(url, { signal: controller.signal });
    await Promise.resolve();
    const rejected = expect(result).rejects.toMatchObject({ name: "AbortError" });
    controller.abort();
    await rejected;
    stalled.reject(new Error("DNS eventually failed"));
    await stalled.promise.catch(() => {});
    // Flush the wrapper's settlement continuation.
    await Promise.resolve();
    transport.mockImplementation(() => Promise.resolve(new Response("recovered")));
    expect(await (await fetch(url)).text()).toBe("recovered");
  });

  test("already-aborted requests never invoke transport or consume capacity", async () => {
    const transport = vi.fn(() => new Response("ok"));
    const fetch = createAbortAwareTransport(transport, 1);
    const controller = new AbortController();
    controller.abort();
    await expect(fetch(new Request(url, { signal: controller.signal }))).rejects.toMatchObject({
      name: "AbortError",
    });
    expect(transport).not.toHaveBeenCalled();
    expect(await (await fetch(url)).text()).toBe("ok");
  });

  test("passes through requests and responses and handles synchronous failures", async () => {
    const response = new Response("metadata");
    const transport = vi.fn(() => response);
    const fetch = createAbortAwareTransport(transport, 1);
    const init = { headers: { Accept: "application/json" } };
    expect(await fetch(url, init)).toBe(response);
    expect(transport).toHaveBeenCalledWith(url, init);
    transport.mockImplementationOnce(() => {
      throw new Error("bad transport input");
    });
    await expect(fetch(url)).rejects.toThrow("bad transport input");
    expect(await fetch(url)).toBe(response);
  });
});
