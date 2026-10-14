import { it } from "@effect/vitest";
import { expect, vi } from "vite-plus/test";
import { once } from "node:events";
import { DatabaseSync } from "node:sqlite";
import { Context, Effect, Exit, Fiber, Schema, Scope } from "effect";
import { generateKeyPair, SignJWT } from "jose";
import { webMcpRequest } from "./mcp.ts";
import { nodeHandler } from "../src/http/application.ts";
import { startGeneration, testSettings } from "./test-issuer.ts";
import { createNodeServer } from "../src/platform/node-http.ts";
import { Database } from "../src/platform/sqlite.ts";
import { Issuer } from "../src/issuer/issuer.ts";
import { Settings } from "../src/issuer/settings.ts";

const settings = testSettings({ baseURL: "https://issuer.example" });

const listen = Effect.gen(function* () {
  const { context: services, scope: generation } = yield* startGeneration();
  yield* Effect.addFinalizer(() => Effect.sync(() => vi.restoreAllMocks()));
  const handlerScope = yield* Scope.fork(yield* Effect.scope, "sequential");

  const listener = yield* nodeHandler().pipe(
    Effect.provideContext(services),
    Scope.provide(handlerScope),
  );

  const server = yield* Effect.acquireRelease(
    Effect.promise(async () => {
      const server = createNodeServer(listener);
      server.listen(0, "127.0.0.1");
      await once(server, "listening");

      return server;
    }),
    (server) =>
      Effect.promise(() => {
        server.closeAllConnections();

        return new Promise<void>((resolve) => server.close(() => resolve()));
      }),
  );

  const { port } = Schema.decodeUnknownSync(Schema.Struct({ port: Schema.Number }))(
    server.address(),
  );

  const shutdown = Scope.close(handlerScope, Exit.void).pipe(
    Effect.andThen(Scope.close(generation, Exit.void)),
  );

  return { services, shutdown, url: `http://127.0.0.1:${port}` };
});

const served = <A, E>(test: Effect.Effect<A, E, Scope.Scope | Settings>) =>
  test.pipe(Effect.scoped, Effect.provide(settings));

it.live("shutdown waits for a provider request to settle after its client disconnects", () =>
  served(
    Effect.gen(function* () {
      const { services, shutdown, url } = yield* listen;
      const entered = Promise.withResolvers<Request>();
      const release = Promise.withResolvers<void>();
      yield* Effect.addFinalizer(() => Effect.sync(() => release.resolve()));
      const destroy = vi.spyOn(Context.get(services, Database).kysely, "destroy");
      vi.spyOn(Context.get(services, Issuer).auth, "handler").mockImplementation(
        async (request) => {
          entered.resolve(request);
          await release.promise;
          // why: this query fails if shutdown closed the database under the provider's work
          await Effect.runPromiseWith(services)(Database.use(({ sql }) => sql`SELECT 1`));

          return Response.json({ keys: [] });
        },
      );
      const controller = new AbortController();

      const response = yield* Effect.forkChild(
        Effect.flip(
          Effect.tryPromise(() => fetch(`${url}/api/auth/jwks`, { signal: controller.signal })),
        ),
      );

      const request = yield* Effect.promise(() => entered.promise);
      expect(request.url).toBe("https://issuer.example/api/auth/jwks");
      controller.abort();
      yield* Fiber.join(response);
      const closing = yield* Effect.forkChild(shutdown, { startImmediately: true });
      expect(destroy).not.toHaveBeenCalled();
      release.resolve();
      yield* Fiber.join(closing);
      expect(destroy).toHaveBeenCalledTimes(1);
    }),
  ),
);

it.live("disconnect does not abandon an uncancellable SDK call in an action route", () =>
  served(
    Effect.gen(function* () {
      const { services, shutdown, url } = yield* listen;
      const { database } = yield* Settings;
      const entered = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      yield* Effect.addFinalizer(() => Effect.sync(() => release.resolve()));
      const destroy = vi.spyOn(Context.get(services, Database).kysely, "destroy");
      const { context } = Context.get(services, Issuer);
      const hash = context.password.hash;
      // why: sign-up hashes inside the provider's transaction, so stalling here holds it open
      vi.spyOn(context.password, "hash").mockImplementation(async (password) => {
        entered.resolve();
        await release.promise;

        return hash(password);
      });
      const controller = new AbortController();

      const response = yield* Effect.forkChild(
        Effect.flip(
          Effect.tryPromise(() =>
            fetch(`${url}/api/setupOwner`, {
              method: "POST",
              headers: { "content-type": "application/json", origin: "https://issuer.example" },
              body: JSON.stringify({
                email: "owner@example.com",
                password: "test-password-long-enough",
              }),
              signal: controller.signal,
            }),
          ),
        ),
      );

      yield* Effect.promise(() => entered.promise);
      controller.abort();
      yield* Fiber.join(response);
      const closing = yield* Effect.forkChild(shutdown, { startImmediately: true });
      expect(destroy).not.toHaveBeenCalled();
      release.resolve();
      yield* Fiber.join(closing);
      expect(destroy).toHaveBeenCalledTimes(1);
      const stored = new DatabaseSync(database);
      expect(stored.prepare("SELECT count(*) AS n FROM user").get()).toEqual({ n: 1 });
      stored.close();
    }),
  ),
);

it.live(
  "an in-process JWKS read is awaited by its request, so shutdown waits for it",
  () =>
    served(
      Effect.gen(function* () {
        const { services, shutdown, url } = yield* listen;
        const entered = Promise.withResolvers<void>();
        const release = Promise.withResolvers<void>();
        yield* Effect.addFinalizer(() => Effect.sync(() => release.resolve()));
        const destroy = vi.spyOn(Context.get(services, Database).kysely, "destroy");
        const { auth } = Context.get(services, Issuer);
        const handler = auth.handler;
        let stalledCallFailed: unknown;

        vi.spyOn(auth, "handler").mockImplementation(async (request) => {
          if (new URL(request.url).pathname.endsWith("/jwks")) {
            entered.resolve();
            await release.promise;
            await Effect.runPromiseWith(services)(Database.use(({ sql }) => sql`SELECT 1`)).catch(
              (cause: unknown) => {
                stalledCallFailed = cause;
              },
            );
          }

          return handler(request);
        });

        const { privateKey } = yield* Effect.promise(() => generateKeyPair("EdDSA"));

        const token = yield* Effect.promise(() =>
          new SignJWT({
            scope: "clankerauth:read clankerauth:write",
            client_id: "stalled",
            azp: "stalled",
          })
            .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid: "unknown" })
            .setIssuer("https://issuer.example/api/auth")
            .setAudience("https://issuer.example/")
            .setSubject("owner")
            .setIssuedAt()
            .setExpirationTime("5m")
            .setJti("stalled")
            .sign(privateKey),
        );

        let answered = false;

        const response = yield* Effect.forkChild(
          Effect.promise(() =>
            fetch(
              webMcpRequest({
                method: "tools/list",
                url: `${url}/mcp`,
                headers: { authorization: `Bearer ${token}` },
              }),
            ),
          ).pipe(
            Effect.tap(() =>
              Effect.sync(() => {
                answered = true;
              }),
            ),
          ),
        );

        yield* Effect.promise(() => entered.promise);
        const closing = yield* Effect.forkChild(shutdown, { startImmediately: true });
        // why: outlasts the deadline a Resource would apply; the raw verifier has none
        yield* Effect.sleep("5500 millis");
        expect(answered).toBe(false);
        expect(destroy).not.toHaveBeenCalled();
        release.resolve();
        yield* Fiber.join(response);
        yield* Fiber.join(closing);
        expect(destroy).toHaveBeenCalledTimes(1);
        expect(stalledCallFailed).toBeUndefined();
      }),
    ),
  15000,
);

it.live.each(["GET", "HEAD"])("%s reaches the provider without a body", (method) =>
  served(
    Effect.gen(function* () {
      const { services, url } = yield* listen;

      const handler = vi
        .spyOn(Context.get(services, Issuer).auth, "handler")
        .mockImplementation(async (request) => {
          expect(request.method).toBe(method);
          expect(request.body).toBeNull();

          return new Response("provider response");
        });

      const response = yield* Effect.promise(() => fetch(`${url}/api/auth/jwks`, { method }));
      expect(response.status).toBe(200);
      expect(yield* Effect.promise(() => response.text())).toBe(
        method === "HEAD" ? "" : "provider response",
      );
      expect(handler).toHaveBeenCalledTimes(1);
    }),
  ),
);

it.live("POST preserves provider body bytes and content type", () =>
  served(
    Effect.gen(function* () {
      const { services, url } = yield* listen;
      const body = ' { "email": "owner@example.internal" }\n';

      const handler = vi
        .spyOn(Context.get(services, Issuer).auth, "handler")
        .mockImplementation(async (request) => {
          expect(request.method).toBe("POST");
          expect(request.headers.get("content-type")).toBe("application/json; charset=utf-8");
          expect(new Uint8Array(await request.arrayBuffer())).toEqual(
            new TextEncoder().encode(body),
          );

          return new Response("ok");
        });

      const response = yield* Effect.promise(() =>
        fetch(`${url}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { "content-type": "application/json; charset=utf-8" },
          body,
        }),
      );

      expect(response.status).toBe(200);
      expect(yield* Effect.promise(() => response.text())).toBe("ok");
      expect(handler).toHaveBeenCalledTimes(1);
    }),
  ),
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
] as const)("authorization resource admission: %s", ([_name, query, status, admitted]) =>
  served(
    Effect.gen(function* () {
      const { services, url } = yield* listen;

      const handler = vi
        .spyOn(Context.get(services, Issuer).auth, "handler")
        .mockResolvedValue(new Response("provider"));

      const response = yield* Effect.promise(() =>
        fetch(`${url}/api/auth/oauth2/authorize${query}`),
      );

      expect(response.status).toBe(status);
      yield* Effect.promise(() => response.text());
      expect(handler).toHaveBeenCalledTimes(admitted ? 1 : 0);
    }),
  ),
);

it.live("bodies above 64 KiB are disconnected before reaching the provider", () =>
  served(
    Effect.gen(function* () {
      const { services, url } = yield* listen;

      const handler = vi
        .spyOn(Context.get(services, Issuer).auth, "handler")
        .mockResolvedValue(new Response("provider"));

      yield* Effect.flip(
        Effect.tryPromise(() =>
          fetch(`${url}/api/auth/oauth2/token`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: `grant_type=${"x".repeat(65536)}`,
          }),
        ),
      );
      expect(handler).not.toHaveBeenCalled();
    }),
  ),
);

it.live("token requests reach the provider without resource pre-checks", () =>
  served(
    Effect.gen(function* () {
      const { services, url } = yield* listen;

      const handler = vi
        .spyOn(Context.get(services, Issuer).auth, "handler")
        .mockResolvedValue(new Response("provider"));

      const response = yield* Effect.promise(() =>
        fetch(`${url}/api/auth/oauth2/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: "grant_type=refresh_token",
        }),
      );

      expect(response.status).toBe(200);
      yield* Effect.promise(() => response.text());
      expect(handler).toHaveBeenCalledTimes(1);
    }),
  ),
);
