import { DatabaseSync } from "node:sqlite";

import { it } from "@effect/vitest";
import { UnreadableRequest } from "@gjermundgaraba/clankerauth-admin-api";
import { Context, Effect, Exit, Fiber, Schema, Scope } from "effect";
import type { Cause } from "effect";
import { constUndefined } from "effect/Function";
import { generateKeyPair, SignJWT } from "jose";
import { expect, vi } from "vite-plus/test";

import { nodeHandler } from "../src/http/application.ts";
import { Issuer } from "../src/issuer/issuer.ts";
import { Settings } from "../src/issuer/settings.ts";
import { listen } from "../src/platform/node-http.ts";
import { Database } from "../src/platform/sqlite.ts";
import { webMcpRequest } from "./mcp.ts";
import { startGeneration, testSettings } from "./test-issuer.ts";

const settings = testSettings({ baseURL: "https://issuer.example" });

const start = Effect.gen(function* () {
  const { context: services, scope: generation } = yield* startGeneration();
  const handlerScope = yield* Scope.fork(yield* Effect.scope, "sequential");
  const listener = yield* listen(0, "127.0.0.1");

  yield* listener.serve(
    yield* nodeHandler().pipe(
      Effect.provideContext(services),
      Scope.provide(handlerScope)
    )
  );

  const shutdown = Scope.close(handlerScope, Exit.void).pipe(
    Effect.andThen(Scope.close(generation, Exit.void))
  );

  return { services, shutdown, url: `http://127.0.0.1:${listener.port}` };
});

const served = <A, E>(test: Effect.Effect<A, E, Scope.Scope | Settings>) =>
  test.pipe(Effect.scoped, Effect.provide(settings));

it.live(
  "shutdown waits for a provider request to settle after its client disconnects",
  () =>
    served(
      Effect.gen(function* () {
        const { services, shutdown, url } = yield* start;
        const entered = Promise.withResolvers<Request>();
        const release = Promise.withResolvers<undefined>();
        yield* Effect.addFinalizer(() =>
          Effect.sync(() => {
            release.resolve(undefined);
          })
        );

        const destroy = vi.spyOn(
          Context.get(services, Database).kysely,
          "destroy"
        );

        vi.spyOn(
          Context.get(services, Issuer).auth,
          "handler"
        ).mockImplementation(async (request) => {
          entered.resolve(request);
          await release.promise;
          // why: this query fails if shutdown closed the database under the provider's work
          await Effect.runPromiseWith(services)(
            Database.use(({ sql }) => sql`SELECT 1`)
          );

          return Response.json({ keys: [] });
        });
        const disconnect = yield* Scope.fork(yield* Effect.scope, "sequential");

        const signal = yield* Effect.abortSignal.pipe(
          Scope.provide(disconnect)
        );

        const response = yield* Effect.forkChild(
          Effect.flip(
            Effect.tryPromise(
              async () => await fetch(`${url}/api/auth/jwks`, { signal })
            )
          )
        );

        const request = yield* Effect.promise(
          async () => await entered.promise
        );

        expect(request.url).toBe("https://issuer.example/api/auth/jwks");
        yield* Scope.close(disconnect, Exit.void);
        yield* Fiber.join(response);

        const closing = yield* Effect.forkChild(shutdown, {
          startImmediately: true,
        });

        expect(destroy).not.toHaveBeenCalled();
        release.resolve(undefined);
        yield* Fiber.join(closing);
        expect(destroy).toHaveBeenCalledOnce();
      })
    )
);

it.live(
  "disconnect does not abandon an uncancellable SDK call in an action route",
  () =>
    served(
      Effect.gen(function* () {
        const { services, shutdown, url } = yield* start;
        const { database } = yield* Settings;
        const entered = Promise.withResolvers<undefined>();
        const release = Promise.withResolvers<undefined>();
        yield* Effect.addFinalizer(() =>
          Effect.sync(() => {
            release.resolve(undefined);
          })
        );

        const destroy = vi.spyOn(
          Context.get(services, Database).kysely,
          "destroy"
        );

        const { context } = Context.get(services, Issuer);
        const { hash } = context.password;
        // why: sign-up hashes inside the provider's transaction, so stalling here holds it open
        vi.spyOn(context.password, "hash").mockImplementation(
          async (password) => {
            entered.resolve(undefined);
            await release.promise;

            return await hash(password);
          }
        );
        const disconnect = yield* Scope.fork(yield* Effect.scope, "sequential");

        const signal = yield* Effect.abortSignal.pipe(
          Scope.provide(disconnect)
        );

        const response = yield* Effect.forkChild(
          Effect.flip(
            Effect.tryPromise(
              async () =>
                await fetch(`${url}/api/setupOwner`, {
                  method: "POST",
                  headers: {
                    "content-type": "application/json",
                    origin: "https://issuer.example",
                  },
                  body: JSON.stringify({
                    email: "owner@example.com",
                    password: "test-password-long-enough",
                  }),
                  signal,
                })
            )
          )
        );

        yield* Effect.promise(async () => {
          await entered.promise;
        });
        yield* Scope.close(disconnect, Exit.void);
        yield* Fiber.join(response);

        const closing = yield* Effect.forkChild(shutdown, {
          startImmediately: true,
        });

        expect(destroy).not.toHaveBeenCalled();
        release.resolve(undefined);
        yield* Fiber.join(closing);
        expect(destroy).toHaveBeenCalledOnce();
        const stored = new DatabaseSync(database);
        expect({
          ...stored.prepare("SELECT count(*) AS n FROM user").get(),
        }).toStrictEqual({ n: 1 });
        stored.close();
      })
    )
);

it.live(
  "an in-process JWKS read is awaited by its request, so shutdown waits for it",
  () =>
    served(
      Effect.gen(function* () {
        const { services, shutdown, url } = yield* start;
        const entered = Promise.withResolvers<undefined>();
        const release = Promise.withResolvers<undefined>();
        yield* Effect.addFinalizer(() =>
          Effect.sync(() => {
            release.resolve(undefined);
          })
        );

        const destroy = vi.spyOn(
          Context.get(services, Database).kysely,
          "destroy"
        );

        const { auth } = Context.get(services, Issuer);
        const { handler } = auth;
        let stalledCallFailed: Cause.Cause<unknown> | undefined;

        vi.spyOn(auth, "handler").mockImplementation(async (request) => {
          if (new URL(request.url).pathname.endsWith("/jwks")) {
            entered.resolve(undefined);
            await release.promise;

            stalledCallFailed = await Effect.runPromiseWith(services)(
              Database.use(({ sql }) => sql`SELECT 1`).pipe(
                Effect.matchCause({
                  onFailure: (cause) => cause,
                  onSuccess: constUndefined,
                })
              )
            );
          }

          return await handler(request);
        });

        const { privateKey } = yield* Effect.promise(
          async () => await generateKeyPair("EdDSA")
        );

        const token = yield* Effect.promise(
          async () =>
            await new SignJWT({
              scope: "clankerauth:read clankerauth:write",
              client_id: "stalled",
              azp: "stalled",
            })
              .setProtectedHeader({
                alg: "EdDSA",
                typ: "at+jwt",
                kid: "unknown",
              })
              .setIssuer("https://issuer.example/api/auth")
              .setAudience("https://issuer.example/")
              .setSubject("owner")
              .setIssuedAt()
              .setExpirationTime("5m")
              .setJti("stalled")
              .sign(privateKey)
        );

        let answered = false;

        const response = yield* Effect.forkChild(
          Effect.promise(
            async () =>
              await fetch(
                webMcpRequest({
                  method: "tools/list",
                  url: `${url}/mcp`,
                  headers: { authorization: `Bearer ${token}` },
                })
              )
          ).pipe(
            Effect.tap(() =>
              Effect.sync(() => {
                answered = true;
              })
            )
          )
        );

        yield* Effect.promise(async () => {
          await entered.promise;
        });

        const closing = yield* Effect.forkChild(shutdown, {
          startImmediately: true,
        });

        // why: outlasts the deadline a Resource would apply; the raw verifier has none
        yield* Effect.sleep("5500 millis");
        expect(answered).toBe(false);
        expect(destroy).not.toHaveBeenCalled();
        release.resolve(undefined);
        yield* Fiber.join(response);
        yield* Fiber.join(closing);
        expect(destroy).toHaveBeenCalledOnce();
        expect(stalledCallFailed).toBeUndefined();
      })
    ),
  15_000
);

it.live.each(["GET", "HEAD"])(
  "%s reaches the provider without a body",
  (method) =>
    served(
      Effect.gen(function* () {
        const { services, url } = yield* start;

        const handler = vi
          .spyOn(Context.get(services, Issuer).auth, "handler")
          .mockImplementation(async (request) => {
            expect(request.method).toBe(method);
            expect(request.body).toBeNull();

            return new Response("provider response");
          });

        const response = yield* Effect.promise(
          async () => await fetch(`${url}/api/auth/jwks`, { method })
        );

        expect(response.status).toBe(200);
        expect(yield* Effect.promise(async () => await response.text())).toBe(
          method === "HEAD" ? "" : "provider response"
        );
        expect(handler).toHaveBeenCalledOnce();
      })
    )
);

it.live("POST preserves provider body bytes and content type", () =>
  served(
    Effect.gen(function* () {
      const { services, url } = yield* start;
      const body = ' { "email": "owner@example.internal" }\n';

      const handler = vi
        .spyOn(Context.get(services, Issuer).auth, "handler")
        .mockImplementation(async (request) => {
          expect(request.method).toBe("POST");
          expect(request.headers.get("content-type")).toBe(
            "application/json; charset=utf-8"
          );
          expect(new Uint8Array(await request.arrayBuffer())).toStrictEqual(
            new TextEncoder().encode(body)
          );

          return new Response("ok");
        });

      const response = yield* Effect.promise(
        async () =>
          await fetch(`${url}/api/auth/sign-in/email`, {
            method: "POST",
            headers: { "content-type": "application/json; charset=utf-8" },
            body,
          })
      );

      expect(response.status).toBe(200);
      expect(yield* Effect.promise(async () => await response.text())).toBe(
        "ok"
      );
      expect(handler).toHaveBeenCalledOnce();
    })
  )
);

it.live.each([
  ["missing resource", "", 400, false],
  ["unknown resource", "?resource=https://unknown.example", 400, false],
  [
    "several resources",
    "?resource=https://issuer.example/&resource=https://issuer.example/",
    400,
    false,
  ],
  ["known resource", "?resource=https://issuer.example/", 200, true],
] as const)(
  "authorization resource admission: %s",
  ([_name, query, status, admitted]) =>
    served(
      Effect.gen(function* () {
        const { services, url } = yield* start;

        const handler = vi
          .spyOn(Context.get(services, Issuer).auth, "handler")
          .mockResolvedValue(new Response("provider"));

        const response = yield* Effect.promise(
          async () => await fetch(`${url}/api/auth/oauth2/authorize${query}`)
        );

        expect(response.status).toBe(status);
        yield* Effect.promise(async () => await response.text());
        expect(handler).toHaveBeenCalledTimes(admitted ? 1 : 0);
      })
    )
);

it.live(
  "bodies above 64 KiB are refused as unreadable before reaching the provider",
  () =>
    served(
      Effect.gen(function* () {
        const { services, url } = yield* start;

        const handler = vi
          .spyOn(Context.get(services, Issuer).auth, "handler")
          .mockResolvedValue(new Response("provider"));

        const response = yield* Effect.promise(
          async () =>
            await fetch(`${url}/api/auth/oauth2/token`, {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: `grant_type=${"x".repeat(65_536)}`,
            })
        );

        expect(response.status).toBe(400);

        const body = yield* Effect.promise(async () => await response.text());

        expect(
          yield* Schema.decodeEffect(Schema.fromJsonString(UnreadableRequest))(
            body
          )
        ).toBeInstanceOf(UnreadableRequest);
        expect(handler).not.toHaveBeenCalled();
      })
    )
);

it.live("token requests reach the provider without resource pre-checks", () =>
  served(
    Effect.gen(function* () {
      const { services, url } = yield* start;

      const handler = vi
        .spyOn(Context.get(services, Issuer).auth, "handler")
        .mockResolvedValue(new Response("provider"));

      const response = yield* Effect.promise(
        async () =>
          await fetch(`${url}/api/auth/oauth2/token`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: "grant_type=refresh_token",
          })
      );

      expect(response.status).toBe(200);
      yield* Effect.promise(async () => await response.text());
      expect(handler).toHaveBeenCalledOnce();
    })
  )
);
