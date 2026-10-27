import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";

import { it } from "@effect/vitest";
import { Effect } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";

import { ProviderUnavailable } from "../src/errors.ts";
import { Verifier } from "../src/index.ts";
import { execute } from "../src/transport.ts";
import { withHttp } from "./support.ts";

const listening = (handler: Parameters<typeof createServer>[1]) =>
  Effect.gen(function* () {
    const server = yield* Effect.acquireRelease(
      Effect.sync(() => createServer(handler)),
      (opened) =>
        Effect.promise(async () => {
          opened.closeAllConnections();
          await opened[Symbol.asyncDispose]();
        })
    );

    server.listen(0, "127.0.0.1");
    yield* Effect.promise(async () => {
      await once(server, "listening");
    });
    const address = server.address();
    assert.ok(
      address !== null && address instanceof Object && "port" in address
    );

    return `http://127.0.0.1:${address.port}`;
  });

it.live(
  "SDK transport preserves Fetch defaults and request headers while rejecting redirects",
  () =>
    Effect.gen(function* () {
      let redirected = 0;

      const url = yield* listening((request, response) => {
        if (request.url === "/redirect") {
          response.writeHead(302, { location: "/target" }).end();

          return;
        }

        if (request.url === "/target") {
          redirected += 1;
        }

        response.end("ok");
      });

      const observed: RequestInit[] = [];

      yield* withHttp(
        Effect.gen(function* () {
          const client = yield* HttpClient.HttpClient;

          const response = yield* execute(
            client,
            HttpClientRequest.get(`${url}/ok`).pipe(
              HttpClientRequest.setHeader("x-app", "request")
            )
          );

          assert.equal(yield* response.text, "ok");

          const redirect = yield* Effect.flip(
            execute(client, HttpClientRequest.get(`${url}/redirect`))
          );

          assert.ok(redirect instanceof ProviderUnavailable);
          assert.equal(redirect.operation, "http.redirect");
        }).pipe(Effect.scoped)
      ).pipe(
        Effect.provideService(FetchHttpClient.RequestInit, {
          headers: { "x-default": "configured", "x-app": "default" },
          cache: "no-store",
          redirect: "follow",
        }),
        Effect.provideService(FetchHttpClient.Fetch, async (input, init) => {
          observed.push(init ?? {});

          return await globalThis.fetch(input, init);
        })
      );

      assert.equal(observed.length, 2);

      for (const init of observed) {
        assert.equal(new Headers(init.headers).get("x-default"), "configured");
        assert.equal(init.cache, "no-store");
        assert.equal(init.redirect, "manual");
        assert.ok(init.signal instanceof AbortSignal);
      }

      for (const init of observed.slice(0, 1)) {
        assert.equal(new Headers(init.headers).get("x-app"), "request");
      }

      assert.equal(redirected, 0);
    })
);

it.live(
  "a verifier refuses to read either document through a redirect, and follows none",
  () =>
    Effect.gen(function* () {
      let followed = 0;

      const url = yield* listening((request, response) => {
        if (request.url?.startsWith("/moved") === true) {
          followed += 1;
          response.end("{}");

          return;
        }

        const status = request.url === "/api/keyList" ? 308 : 307;
        response.writeHead(status, { location: `/moved${request.url}` }).end();
      });

      const verifier = yield* withHttp(
        Verifier.make({
          issuer: `${url}/api/auth`,
          resource: "https://notes.example/",
          store: Verifier.store(),
        })
      );

      const header = Buffer.from(
        JSON.stringify({ alg: "EdDSA", kid: "k", typ: "at+jwt" })
      );

      for (const token of [
        `${header.toString("base64url")}.e30.AA`,
        `clankerauth_${"k".repeat(64)}`,
      ]) {
        const refused = yield* Effect.flip(verifier.verifyToken(token));
        assert.ok(refused instanceof ProviderUnavailable);
        assert.equal(refused.operation, "http.redirect");
      }

      assert.equal(followed, 0);
    })
);
