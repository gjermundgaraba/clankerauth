import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { test } from "vite-plus/test";
import { Effect } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/unstable/http";
import { ProviderUnavailable } from "../src/index.ts";
import { execute } from "../src/transport.ts";
import { withHttp } from "./support.ts";

test("SDK transport preserves Fetch defaults and request headers while rejecting redirects", async () => {
  let redirected = 0;

  const server = createServer((request, response) => {
    if (request.url === "/redirect") {
      response.writeHead(302, { location: "/target" }).end();

      return;
    }

    if (request.url === "/target") redirected++;
    response.end("ok");
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert(address !== null && address instanceof Object && "port" in address);
  const url = `http://127.0.0.1:${address.port}`;
  const observed: RequestInit[] = [];

  try {
    await Effect.runPromise(
      withHttp(
        Effect.gen(function* () {
          const client = yield* HttpClient.HttpClient;

          const response = yield* execute(
            client,
            HttpClientRequest.get(`${url}/ok`).pipe(
              HttpClientRequest.setHeader("x-app", "request"),
            ),
          );

          assert.equal(yield* response.text, "ok");

          assert(
            (yield* Effect.flip(
              execute(client, HttpClientRequest.get(`${url}/redirect`)),
            )) instanceof ProviderUnavailable,
          );
        }).pipe(Effect.scoped),
      ).pipe(
        Effect.provideService(FetchHttpClient.RequestInit, {
          headers: { "x-default": "configured", "x-app": "default" },
          cache: "no-store",
          redirect: "follow",
        }),
        Effect.provideService(FetchHttpClient.Fetch, (input, init) => {
          observed.push(init ?? {});

          return globalThis.fetch(input, init);
        }),
      ),
    );

    assert.equal(observed.length, 2);

    for (const init of observed) {
      assert.equal(new Headers(init.headers).get("x-default"), "configured");
      assert.equal(init.cache, "no-store");
      assert.equal(init.redirect, "error");
      assert(init.signal instanceof AbortSignal);
    }

    for (const init of observed.slice(0, 1))
      assert.equal(new Headers(init.headers).get("x-app"), "request");
    assert.equal(redirected, 0);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
