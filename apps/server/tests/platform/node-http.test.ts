import { request } from "node:http";

import { NodeHttpServer } from "@effect/platform-node";
import { it } from "@effect/vitest";
import {
  Data,
  Deferred,
  Effect,
  Exit,
  Fiber,
  Result,
  Scope,
  Stream,
} from "effect";
import { HttpServerRequest, HttpServerResponse } from "effect/http";
import { expect, vi } from "vite-plus/test";

import {
  createNodeServer,
  listen,
  peerHeader,
  requestPolicy,
} from "../../src/platform/node-http.ts";

const baseURL = "https://issuer.example";

class PrivateFailure extends Data.TaggedError("PrivateFailure")<{
  readonly message: string;
}> {}

const privateFailure = new PrivateFailure({
  message: "private failure details",
});

const serve = Effect.fnUntraced(function* <E>(
  handler: Effect.Effect<
    HttpServerResponse.HttpServerResponse,
    E,
    HttpServerRequest.HttpServerRequest | Scope.Scope
  >,
  trustProxy = false
) {
  const scope = yield* Scope.fork(yield* Effect.scope, "sequential");
  const listener = yield* listen(0, "127.0.0.1").pipe(Scope.provide(scope));

  const nodeHandler = yield* NodeHttpServer.makeHandler(
    requestPolicy({ baseURL, trustProxy })(handler),
    { scope }
  );

  yield* listener.serve(nodeHandler).pipe(Scope.provide(scope));

  return { scope, url: `http://127.0.0.1:${listener.port}` };
});

const rawRequest = (url: string, path: string) =>
  Effect.callback<number | undefined>((resume) => {
    const req = request(url, { path }, (res) => {
      res.on("error", (error) => {
        resume(Effect.die(error));
      });
      res.on("end", () => {
        resume(Effect.succeed(res.statusCode));
      });
      res.resume();
    });

    req.on("error", (error) => {
      resume(Effect.die(error));
    });
    req.end();
  });

it.live(
  "canonical request URL, trusted peer, body and multiple cookies survive native HTTP",
  () =>
    Effect.gen(function* () {
      const called = vi.fn<() => void>();

      const { url } = yield* serve(
        Effect.gen(function* () {
          const req = yield* HttpServerRequest.HttpServerRequest;
          expect(req.url).toBe("/path?query=value");
          expect(req.headers["host"]).toBe("issuer.example");
          expect(req.method).toBe("POST");
          expect(yield* req.text).toBe("payload");

          for (const name of [
            "forwarded",
            "x-forwarded-host",
            "x-forwarded-proto",
          ]) {
            expect(req.headers[name]).toBeUndefined();
          }

          expect(req.headers[peerHeader]).toBe("127.0.0.1");
          expect(req.headers["cookie"]).toBe("session=owner");
          called();

          return HttpServerResponse.fromWeb(
            new Response("created", {
              status: 201,
              headers: [
                ["set-cookie", "a=1"],
                ["set-cookie", "b=2"],
              ],
            })
          );
        })
      );

      expect(createNodeServer().requestTimeout).toBe(15_000);
      expect(createNodeServer().headersTimeout).toBe(10_000);

      const response = yield* Effect.promise(
        async () =>
          await fetch(`${url}/path?query=value`, {
            method: "POST",
            headers: {
              host: "evil.example",
              forwarded: "for=evil",
              "x-forwarded-host": "evil.example",
              "x-forwarded-proto": "http",
              [peerHeader]: "forged",
              cookie: "session=owner",
            },
            body: "payload",
          })
      );

      expect(response.status).toBe(201);
      expect(response.headers.getSetCookie()).toStrictEqual(["a=1", "b=2"]);
      expect(yield* Effect.promise(async () => await response.text())).toBe(
        "created"
      );
      expect(called).toHaveBeenCalledOnce();
    })
);

it.live(
  "the forward-auth check alone keeps the proxy's forwarded host and scheme",
  () =>
    Effect.gen(function* () {
      const { url } = yield* serve(
        Effect.gen(function* () {
          const req = yield* HttpServerRequest.HttpServerRequest;
          expect(req.headers["host"]).toBe("issuer.example");
          expect(req.headers["forwarded"]).toBeUndefined();
          const kept = req.url.split("?")[0] === "/forward-auth";
          expect(req.headers["x-forwarded-host"]).toBe(
            kept ? "notes.example" : undefined
          );
          expect(req.headers["x-forwarded-proto"]).toBe(
            kept ? "https" : undefined
          );

          return HttpServerResponse.empty({ status: 204 });
        })
      );

      const headers = {
        forwarded: "for=evil",
        "x-forwarded-host": "notes.example",
        "x-forwarded-proto": "https",
      };

      expect(
        (yield* Effect.promise(
          async () => await fetch(`${url}/forward-auth?resource=x`, { headers })
        )).status
      ).toBe(204);
      expect(
        (yield* Effect.promise(
          async () => await fetch(`${url}/forward-auth/logout`, { headers })
        )).status
      ).toBe(204);
    })
);

it.live(
  "a trusted proxy's last X-Forwarded-For hop becomes the peer address",
  () =>
    Effect.gen(function* () {
      const peers: string[] = [];

      const { url } = yield* serve(
        Effect.gen(function* () {
          const req = yield* HttpServerRequest.HttpServerRequest;
          peers.push(req.headers[peerHeader] ?? "");
          expect(req.headers["x-forwarded-for"]).toBeUndefined();

          return HttpServerResponse.empty();
        }),
        true
      );

      yield* Effect.promise(
        async () =>
          await fetch(url, {
            headers: { "x-forwarded-for": "203.0.113.9, 10.0.0.2" },
          })
      );
      yield* Effect.promise(async () => await fetch(url));
      expect(peers).toStrictEqual(["10.0.0.2", "127.0.0.1"]);
    })
);

it.live("rejects non-origin request targets before calling the handler", () =>
  Effect.gen(function* () {
    const called = vi.fn<() => HttpServerResponse.HttpServerResponse>(() =>
      HttpServerResponse.text("unexpected")
    );

    const { url } = yield* serve(Effect.sync(called));

    for (const path of [
      "//evil.example/path",
      "http://evil.example/path",
      "*",
    ]) {
      expect(yield* rawRequest(url, path)).toBe(400);
    }

    expect(called).not.toHaveBeenCalled();
  })
);

it.live("handler failure produces a generic 500 without leaking details", () =>
  Effect.gen(function* () {
    const { url } = yield* serve(Effect.fail(privateFailure));

    const response = yield* Effect.promise(async () => await fetch(url));
    expect(response.status).toBe(500);
    expect(
      yield* Effect.promise(async () => await response.text())
    ).not.toContain("private failure details");
  })
);

it.live.each([false, true])(
  "responses stream before completion; late failure=%s",
  (fail) =>
    Effect.gen(function* () {
      const release = yield* Deferred.make<undefined>();

      const next = Deferred.await(release).pipe(
        Effect.andThen(
          fail
            ? Effect.fail(privateFailure)
            : Effect.succeed(Buffer.from("second"))
        )
      );

      const { url } = yield* serve(
        Effect.succeed(
          HttpServerResponse.stream(
            Stream.concat(
              Stream.succeed(Buffer.from("first")),
              Stream.fromEffect(next)
            ),
            { status: 201 }
          )
        )
      );

      const response = yield* Effect.promise(async () => await fetch(url));
      expect(response.status).toBe(201);
      const reader = response.body?.getReader();

      if (!reader) {
        return yield* Effect.die(new Error("Missing response stream"));
      }

      yield* Effect.addFinalizer(() =>
        Effect.promise(async () => {
          await reader.cancel().catch(() => {});
        })
      );
      yield* Effect.addFinalizer(() => Deferred.succeed(release, undefined));
      const first = yield* Effect.promise(async () => await reader.read());
      expect(Buffer.from(first.value ?? []).toString()).toBe("first");
      yield* Deferred.succeed(release, undefined);

      if (fail) {
        yield* Effect.flip(Effect.tryPromise(async () => await reader.read()));
      } else {
        expect(
          Buffer.from(
            (yield* Effect.promise(async () => await reader.read())).value ?? []
          ).toString()
        ).toBe("second");
        expect(
          (yield* Effect.promise(async () => await reader.read())).done
        ).toBe(true);
      }
    })
);

it.live("disconnect interrupts native work and runs request finalizers", () =>
  Effect.gen(function* () {
    const entered = Promise.withResolvers<undefined>();
    const finalized = Promise.withResolvers<undefined>();

    const release = vi.fn<() => void>(() => {
      finalized.resolve(undefined);
    });

    const { url } = yield* serve(
      Effect.gen(function* () {
        yield* Effect.addFinalizer(() => Effect.sync(release));
        entered.resolve(undefined);

        return yield* Effect.never;
      })
    );

    const response = yield* Effect.forkChild(
      Effect.promise(async (signal) => await fetch(url, { signal }))
    );

    yield* Effect.promise(async () => {
      await entered.promise;
    });
    yield* Fiber.interrupt(response);
    yield* Effect.promise(async () => {
      await finalized.promise;
    });
    expect(release).toHaveBeenCalledOnce();
  })
);

it.live("an immediately failing response stream cannot appear successful", () =>
  Effect.gen(function* () {
    const { url } = yield* serve(
      Effect.succeed(
        HttpServerResponse.stream(Stream.fail(privateFailure), {
          status: 201,
        })
      )
    );

    const outcome = yield* Effect.exit(
      Effect.tryPromise(
        async () =>
          await fetch(url).then(async (response) => await response.text())
      )
    );

    expect(Exit.isFailure(outcome)).toBe(true);
  })
);

it.live(
  "streaming retains the request scope until the client disconnects",
  () =>
    Effect.gen(function* () {
      const finalized = Promise.withResolvers<undefined>();

      const release = vi.fn<() => void>(() => {
        finalized.resolve(undefined);
      });

      const { url } = yield* serve(
        Effect.gen(function* () {
          yield* Effect.addFinalizer(() => Effect.sync(release));

          return HttpServerResponse.stream(
            Stream.concat(Stream.succeed(Buffer.from("first")), Stream.never)
          );
        })
      );

      const connection = yield* Scope.fork(yield* Effect.scope, "sequential");
      const signal = yield* Effect.abortSignal.pipe(Scope.provide(connection));

      const response = yield* Effect.promise(
        async () => await fetch(url, { signal })
      );

      const reader = response.body?.getReader();

      if (!reader) {
        return yield* Effect.die(new Error("Missing response stream"));
      }

      expect(
        Buffer.from(
          (yield* Effect.promise(async () => await reader.read())).value ?? []
        ).toString()
      ).toBe("first");
      expect(release).not.toHaveBeenCalled();
      yield* Scope.close(connection, Exit.void);
      yield* Effect.promise(async () => {
        await finalized.promise;
      });
      expect(release).toHaveBeenCalledOnce();
    })
);

it.live(
  "shutdown interrupts an open response stream before closing request scopes",
  () =>
    Effect.gen(function* () {
      const finalized = vi.fn<() => void>();

      const { scope, url } = yield* serve(
        Effect.gen(function* () {
          yield* Effect.addFinalizer(() => Effect.sync(finalized));

          return HttpServerResponse.stream(
            Stream.concat(Stream.succeed(Buffer.from("first")), Stream.never)
          );
        }).pipe(Effect.uninterruptible)
      );

      const signal = yield* Effect.abortSignal;

      const response = yield* Effect.promise(
        async () => await fetch(url, { signal })
      );

      const reader = response.body?.getReader();

      if (!reader) {
        return yield* Effect.die(new Error("Missing response stream"));
      }

      expect(
        Buffer.from(
          (yield* Effect.promise(async () => await reader.read())).value ?? []
        ).toString()
      ).toBe("first");

      const disconnected = yield* Effect.forkChild(
        Effect.result(Effect.tryPromise(async () => await reader.read())),
        { startImmediately: true }
      );

      yield* Scope.close(scope, Exit.void);
      const read = yield* Fiber.join(disconnected);
      expect(Result.isFailure(read) || read.success.done).toBe(true);
      expect(finalized).toHaveBeenCalledOnce();
    })
);
