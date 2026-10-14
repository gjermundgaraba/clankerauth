import { it } from "@effect/vitest";
import { expect, vi } from "vite-plus/test";
import { request } from "node:http";
import { Deferred, Effect, Exit, Fiber, Scope, Stream } from "effect";
import { NodeHttpServer } from "@effect/platform-node";
import { HttpServerRequest, HttpServerResponse } from "effect/http";
import { createNodeServer, listen, requestPolicy } from "../../src/platform/node-http.ts";

const baseURL = "https://issuer.example";

const serve = Effect.fnUntraced(function* <E>(
  handler: Effect.Effect<
    HttpServerResponse.HttpServerResponse,
    E,
    HttpServerRequest.HttpServerRequest | Scope.Scope
  >,
  trustProxy = false,
) {
  const scope = yield* Scope.fork(yield* Effect.scope, "sequential");
  const listener = yield* listen(0, "127.0.0.1").pipe(Scope.provide(scope));

  const nodeHandler = yield* NodeHttpServer.makeHandler(
    requestPolicy({ baseURL, trustProxy })(handler),
    { scope },
  );

  yield* listener.serve(nodeHandler).pipe(Scope.provide(scope));

  return { scope, url: `http://127.0.0.1:${listener.port}` };
});

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

it.live("canonical request URL, trusted peer, body and multiple cookies survive native HTTP", () =>
  Effect.gen(function* () {
    const called = vi.fn();

    const { url } = yield* serve(
      Effect.gen(function* () {
        const req = yield* HttpServerRequest.HttpServerRequest;
        expect(req.url).toBe("/path?query=value");
        expect(req.headers.host).toBe("issuer.example");
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

    expect(createNodeServer().requestTimeout).toBe(15000);
    expect(createNodeServer().headersTimeout).toBe(10000);

    const response = yield* Effect.promise(() =>
      fetch(`${url}/path?query=value`, {
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
      }),
    );

    expect(response.status).toBe(201);
    expect(response.headers.getSetCookie()).toEqual(["a=1", "b=2"]);
    expect(yield* Effect.promise(() => response.text())).toBe("created");
    expect(called).toHaveBeenCalledTimes(1);
  }),
);

it.live("the forward-auth check alone keeps the proxy's forwarded host and scheme", () =>
  Effect.gen(function* () {
    const { url } = yield* serve(
      Effect.gen(function* () {
        const req = yield* HttpServerRequest.HttpServerRequest;
        expect(req.headers.host).toBe("issuer.example");
        expect(req.headers.forwarded).toBeUndefined();
        const kept = req.url.split("?")[0] === "/forward-auth";
        expect(req.headers["x-forwarded-host"]).toBe(kept ? "notes.example" : undefined);
        expect(req.headers["x-forwarded-proto"]).toBe(kept ? "https" : undefined);

        return HttpServerResponse.empty({ status: 204 });
      }),
    );

    const headers = {
      forwarded: "for=evil",
      "x-forwarded-host": "notes.example",
      "x-forwarded-proto": "https",
    };

    expect(
      (yield* Effect.promise(() => fetch(`${url}/forward-auth?resource=x`, { headers }))).status,
    ).toBe(204);
    expect(
      (yield* Effect.promise(() => fetch(`${url}/forward-auth/logout`, { headers }))).status,
    ).toBe(204);
  }),
);

it.live("a trusted proxy's last X-Forwarded-For hop becomes the peer address", () =>
  Effect.gen(function* () {
    const peers: string[] = [];

    const { url } = yield* serve(
      Effect.gen(function* () {
        const req = yield* HttpServerRequest.HttpServerRequest;
        peers.push(req.headers["x-clankerauth-peer"] ?? "");
        expect(req.headers["x-forwarded-for"]).toBeUndefined();

        return HttpServerResponse.empty();
      }),
      true,
    );

    yield* Effect.promise(() =>
      fetch(url, { headers: { "x-forwarded-for": "203.0.113.9, 10.0.0.2" } }),
    );
    yield* Effect.promise(() => fetch(url));
    expect(peers).toEqual(["10.0.0.2", "127.0.0.1"]);
  }),
);

it.live("rejects non-origin request targets before calling the handler", () =>
  Effect.gen(function* () {
    const called = vi.fn(() => HttpServerResponse.text("unexpected"));
    const { url } = yield* serve(Effect.sync(called));

    for (const path of ["//evil.example/path", "http://evil.example/path", "*"])
      expect(yield* Effect.promise(() => rawRequest(url, path))).toBe(400);
    expect(called).not.toHaveBeenCalled();
  }),
);

it.live("handler failure produces a generic 500 without leaking details", () =>
  Effect.gen(function* () {
    const { url } = yield* serve(Effect.fail(new Error("private failure details")));
    const response = yield* Effect.promise(() => fetch(url));
    expect(response.status).toBe(500);
    expect(yield* Effect.promise(() => response.text())).not.toContain("private failure details");
  }),
);

it.live.each([false, true])("responses stream before completion; late failure=%s", (fail) =>
  Effect.gen(function* () {
    const release = yield* Deferred.make<void>();

    const next = Deferred.await(release).pipe(
      Effect.andThen(
        fail
          ? Effect.fail(new Error("private failure details"))
          : Effect.succeed(Buffer.from("second")),
      ),
    );

    const { url } = yield* serve(
      Effect.succeed(
        HttpServerResponse.stream(
          Stream.concat(Stream.succeed(Buffer.from("first")), Stream.fromEffect(next)),
          { status: 201 },
        ),
      ),
    );

    const response = yield* Effect.promise(() => fetch(url));
    expect(response.status).toBe(201);
    const reader = response.body?.getReader();

    if (!reader) return yield* Effect.die(new Error("Missing response stream"));

    yield* Effect.addFinalizer(() => Effect.promise(() => reader.cancel().catch(() => {})));
    yield* Effect.addFinalizer(() => Deferred.succeed(release, undefined));
    const first = yield* Effect.promise(() => reader.read());
    expect(Buffer.from(first.value ?? []).toString()).toBe("first");
    yield* Deferred.succeed(release, undefined);

    if (fail) yield* Effect.flip(Effect.tryPromise(() => reader.read()));
    else {
      expect(Buffer.from((yield* Effect.promise(() => reader.read())).value ?? []).toString()).toBe(
        "second",
      );
      expect((yield* Effect.promise(() => reader.read())).done).toBe(true);
    }
  }),
);

it.live("disconnect interrupts native work and runs request finalizers", () =>
  Effect.gen(function* () {
    const entered = Promise.withResolvers<void>();
    const finalized = Promise.withResolvers<void>();

    const { url } = yield* serve(
      Effect.gen(function* () {
        yield* Effect.addFinalizer(() => Effect.sync(() => finalized.resolve()));
        entered.resolve();

        return yield* Effect.never;
      }),
    );

    const controller = new AbortController();

    const response = yield* Effect.forkChild(
      Effect.flip(Effect.tryPromise(() => fetch(url, { signal: controller.signal }))),
    );

    yield* Effect.promise(() => entered.promise);
    controller.abort();
    yield* Fiber.join(response);
    yield* Effect.promise(() => finalized.promise);
  }),
);

it.live("an immediately failing response stream cannot appear successful", () =>
  Effect.gen(function* () {
    const { url } = yield* serve(
      Effect.succeed(
        HttpServerResponse.stream(Stream.fail(new Error("private failure details")), {
          status: 201,
        }),
      ),
    );

    yield* Effect.flip(Effect.tryPromise(() => fetch(url).then((response) => response.text())));
  }),
);

it.live("streaming retains the request scope until the client disconnects", () =>
  Effect.gen(function* () {
    const finalized = Promise.withResolvers<void>();
    const release = vi.fn(() => finalized.resolve());

    const { url } = yield* serve(
      Effect.gen(function* () {
        yield* Effect.addFinalizer(() => Effect.sync(release));

        return HttpServerResponse.stream(
          Stream.concat(Stream.succeed(Buffer.from("first")), Stream.never),
        );
      }),
    );

    const controller = new AbortController();
    yield* Effect.addFinalizer(() => Effect.sync(() => controller.abort()));

    const response = yield* Effect.promise(() => fetch(url, { signal: controller.signal }));
    const reader = response.body?.getReader();

    if (!reader) return yield* Effect.die(new Error("Missing response stream"));
    expect(Buffer.from((yield* Effect.promise(() => reader.read())).value ?? []).toString()).toBe(
      "first",
    );
    expect(release).not.toHaveBeenCalled();
    controller.abort();
    yield* Effect.promise(() => finalized.promise);
    expect(release).toHaveBeenCalledTimes(1);
  }),
);

it.live("shutdown interrupts an open response stream before closing request scopes", () =>
  Effect.gen(function* () {
    const finalized = vi.fn();

    const { scope, url } = yield* serve(
      Effect.gen(function* () {
        yield* Effect.addFinalizer(() => Effect.sync(finalized));

        return HttpServerResponse.stream(
          Stream.concat(Stream.succeed(Buffer.from("first")), Stream.never),
        );
      }).pipe(Effect.uninterruptible),
    );

    const controller = new AbortController();
    yield* Effect.addFinalizer(() => Effect.sync(() => controller.abort()));

    const response = yield* Effect.promise(() => fetch(url, { signal: controller.signal }));
    const reader = response.body?.getReader();

    if (!reader) return yield* Effect.die(new Error("Missing response stream"));
    expect(Buffer.from((yield* Effect.promise(() => reader.read())).value ?? []).toString()).toBe(
      "first",
    );

    // why: shutdown may end the stream cleanly or abort its connection
    const disconnected = reader.read().then(
      (result) => expect(result.done).toBe(true),
      () => {},
    );

    yield* Scope.close(scope, Exit.void);
    yield* Effect.promise(() => disconnected);
    expect(finalized).toHaveBeenCalledTimes(1);
  }),
);
