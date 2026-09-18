import { afterEach, expect, test, vi } from "vite-plus/test";
import { request } from "node:http";
import { Deferred, Effect, Exit, Schema, Scope, Stream } from "effect";
import { NodeHttpServer } from "@effect/platform-node";
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import { createNodeServer, requestPolicy } from "../src/node-http.ts";

const scopes: Scope.Closeable[] = [];

const ListenAddress = Schema.Struct({ port: Schema.Number });

const baseURL = "https://issuer.example";

afterEach(async () => {
  for (const scope of scopes.splice(0)) await Effect.runPromise(Scope.close(scope, Exit.void));
});

async function listen<E>(
  handler: Effect.Effect<
    HttpServerResponse.HttpServerResponse,
    E,
    HttpServerRequest.HttpServerRequest | Scope.Scope
  >,
) {
  const scope = Scope.makeUnsafe();
  scopes.push(scope);
  const server = createNodeServer();
  await Effect.runPromise(
    Effect.gen(function* () {
      const http = yield* NodeHttpServer.make(() => server, {
        port: 0,
        host: "127.0.0.1",
        disablePreemptiveShutdown: true,
      });

      yield* http.serve(requestPolicy(baseURL)(handler));
      yield* Effect.addFinalizer(() =>
        Effect.sync(() => {
          server.close();
          server.closeAllConnections();
        }),
      );
    }).pipe(Effect.provideService(Scope.Scope, scope)),
  );
  const { port } = Schema.decodeUnknownSync(ListenAddress)(server.address());

  return { scope, server, url: `http://127.0.0.1:${port}` };
}

const rawRequest = (url: string, path: string) =>
  new Promise<number | undefined>((resolve, reject) => {
    const req = request(url, { path }, (res) => {
      res.on("error", reject);
      res.on("end", () => resolve(res.statusCode));
      res.resume();
    });

    req.on("error", reject);
    req.end();
  });

test("canonical request URL, trusted peer, body and multiple cookies survive native HTTP", async () => {
  const called = vi.fn();

  const { server, url } = await listen(
    Effect.gen(function* () {
      const req = yield* HttpServerRequest.HttpServerRequest;
      expect(req.originalUrl).toBe(`${baseURL}/path?query=value`);
      expect(req.method).toBe("POST");
      expect(yield* req.text).toBe("payload");

      for (const name of ["forwarded", "x-forwarded-host", "x-forwarded-proto"])
        expect(req.headers[name]).toBeUndefined();
      expect(req.headers["x-clankerauth-peer"]).toBe("127.0.0.1");
      expect(req.headers.cookie).toBe("session=owner");
      called();

      return HttpServerResponse.fromWeb(
        new Response("created", {
          status: 201,
          headers: [
            ["set-cookie", "a=1"],
            ["set-cookie", "b=2"],
          ],
        }),
      );
    }),
  );

  expect(server.requestTimeout).toBe(15000);
  expect(server.headersTimeout).toBe(10000);

  const response = await fetch(`${url}/path?query=value`, {
    method: "POST",
    headers: {
      host: "evil.example",
      forwarded: "for=evil",
      "x-forwarded-host": "evil.example",
      "x-forwarded-proto": "http",
      "x-clankerauth-peer": "forged",
      cookie: "session=owner",
    },
    body: "payload",
  });

  expect(response.status).toBe(201);
  expect(response.headers.getSetCookie()).toEqual(["a=1", "b=2"]);
  expect(await response.text()).toBe("created");
  expect(called).toHaveBeenCalledTimes(1);
});

test("rejects non-origin request targets before calling the handler", async () => {
  const called = vi.fn(() => HttpServerResponse.text("unexpected"));
  const { url } = await listen(Effect.sync(called));

  for (const path of ["//evil.example/path", "http://evil.example/path", "*"])
    expect(await rawRequest(url, path)).toBe(400);
  expect(called).not.toHaveBeenCalled();
});

test("accepts exactly 64 KiB and rejects larger bodies before invoking the handler", async () => {
  const called = vi.fn();

  const { url } = await listen(
    Effect.gen(function* () {
      called();
      const request = yield* HttpServerRequest.HttpServerRequest;

      return HttpServerResponse.text(String((yield* request.arrayBuffer).byteLength));
    }),
  );

  const accepted = await fetch(url, { method: "POST", body: "x".repeat(65536) });
  expect(accepted.status).toBe(200);
  expect(await accepted.text()).toBe("65536");
  const rejected = await fetch(url, { method: "POST", body: "x".repeat(65537) });
  expect(rejected.status).toBe(413);
  await rejected.body?.cancel();
  expect(called).toHaveBeenCalledTimes(1);
});

test("chunked oversized bodies are rejected even when the handler ignores the body", async () => {
  const called = vi.fn(() => HttpServerResponse.text("unexpected"));
  const { url } = await listen(Effect.sync(called));

  const status = await new Promise<number | undefined>((resolve, reject) => {
    const req = request(url, { method: "POST" }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });

    req.on("error", reject);
    req.write("x".repeat(65536));
    req.end("x");
  });

  expect(status).toBe(413);
  expect(called).not.toHaveBeenCalled();
});

test("handler failure produces a generic 500 without leaking details", async () => {
  const { url } = await listen(Effect.fail(new Error("private failure details")));
  const response = await fetch(url);
  expect(response.status).toBe(500);
  expect(await response.text()).not.toContain("private failure details");
});

test.each([false, true])("responses stream before completion; late failure=%s", async (fail) => {
  const release = Deferred.makeUnsafe<void>();

  const next = Deferred.await(release).pipe(
    Effect.andThen(
      fail
        ? Effect.fail(new Error("private failure details"))
        : Effect.succeed(Buffer.from("second")),
    ),
  );

  const { url } = await listen(
    Effect.succeed(
      HttpServerResponse.stream(
        Stream.concat(Stream.succeed(Buffer.from("first")), Stream.fromEffect(next)),
        { status: 201 },
      ),
    ),
  );

  const response = await fetch(url);
  expect(response.status).toBe(201);
  const reader = response.body?.getReader();

  if (!reader) throw new Error("Missing response stream");

  try {
    const first = await reader.read();
    expect(Buffer.from(first.value ?? []).toString()).toBe("first");
    await Effect.runPromise(Deferred.succeed(release, undefined));

    if (fail) await expect(reader.read()).rejects.toThrow();
    else {
      expect(Buffer.from((await reader.read()).value ?? []).toString()).toBe("second");
      expect((await reader.read()).done).toBe(true);
    }
  } finally {
    await Effect.runPromise(Deferred.succeed(release, undefined));
    await reader.cancel().catch(() => {});
  }
});

test("disconnect interrupts native work and runs request finalizers", async () => {
  const entered = Promise.withResolvers<void>();
  const finalized = Promise.withResolvers<void>();

  const { url } = await listen(
    Effect.gen(function* () {
      yield* Effect.addFinalizer(() => Effect.sync(() => finalized.resolve()));
      entered.resolve();

      return yield* Effect.never;
    }),
  );

  const controller = new AbortController();
  const response = fetch(url, { signal: controller.signal });
  const rejected = expect(response).rejects.toThrow();
  await entered.promise;
  controller.abort();
  await rejected;
  await finalized.promise;
});

test("an immediately failing response stream cannot appear successful", async () => {
  const { url } = await listen(
    Effect.succeed(
      HttpServerResponse.stream(Stream.fail(new Error("private failure details")), { status: 201 }),
    ),
  );

  await expect(fetch(url).then((response) => response.text())).rejects.toThrow();
});

test("streaming retains the request scope until the client disconnects", async () => {
  const finalized = Promise.withResolvers<void>();
  const release = vi.fn(() => finalized.resolve());

  const { url } = await listen(
    Effect.gen(function* () {
      yield* Effect.addFinalizer(() => Effect.sync(release));

      return HttpServerResponse.stream(
        Stream.concat(Stream.succeed(Buffer.from("first")), Stream.never),
      );
    }),
  );

  const controller = new AbortController();

  try {
    const response = await fetch(url, { signal: controller.signal });
    const reader = response.body?.getReader();

    if (!reader) throw new Error("Missing response stream");
    expect(Buffer.from((await reader.read()).value ?? []).toString()).toBe("first");
    expect(release).not.toHaveBeenCalled();
    controller.abort();
    await finalized.promise;
    expect(release).toHaveBeenCalledTimes(1);
  } finally {
    controller.abort();
  }
});

test("shutdown interrupts an open response stream before closing request scopes", async () => {
  const finalized = vi.fn();

  const { scope, url } = await listen(
    Effect.gen(function* () {
      yield* Effect.addFinalizer(() => Effect.sync(finalized));

      return HttpServerResponse.stream(
        Stream.concat(Stream.succeed(Buffer.from("first")), Stream.never),
      );
    }).pipe(Effect.uninterruptible),
  );

  const controller = new AbortController();

  try {
    const response = await fetch(url, { signal: controller.signal });
    const reader = response.body?.getReader();

    if (!reader) throw new Error("Missing response stream");
    expect(Buffer.from((await reader.read()).value ?? []).toString()).toBe("first");

    // Shutdown may end the stream cleanly or abort its connection.
    const disconnected = reader.read().then(
      (result) => expect(result.done).toBe(true),
      () => {},
    );

    await Effect.runPromise(Scope.close(scope, Exit.void));
    await disconnected;
    expect(finalized).toHaveBeenCalledTimes(1);
  } finally {
    controller.abort();
  }
});
