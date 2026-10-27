import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer, IncomingMessage, request } from "node:http";
import { Socket } from "node:net";
import type { Duplex } from "node:stream";

import { describe, expect, expectTypeOf, it } from "@effect/vitest";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { checkResourceAllowed } from "@modelcontextprotocol/client";
import { Effect, Schema } from "effect";

import { Resource } from "../src/effect-actions.ts";
import { ProviderUnavailable } from "../src/errors.ts";
import { Verifier } from "../src/index.ts";
import { CurrentPrincipal } from "../src/session.ts";
import type { Caller } from "../src/session.ts";
import {
  authorize,
  Login,
  Notes,
  publicUrl,
  resourceOf,
  sent,
  startIssuer,
  withHttp,
} from "./support.ts";

const read = Action.make("read", {
  description: "Read",
  readOnly: true,
  caller: CurrentPrincipal,
  success: Schema.String,
});

const write = Action.make("write", {
  description: "Write",
  readOnly: false,
  caller: CurrentPrincipal,
  success: Schema.String,
});

const guarded = {
  scopes: ["notes:read", "notes:write"],
  required: "notes:read",
} as const;

const resourceFor = (issuer: string) =>
  withHttp(
    resourceOf({
      issuer,
      publicUrl: new URL(publicUrl),
      store: Verifier.store(),
      ...guarded,
    })
  );

const decide = (
  check: Effect.Effect<void, Action.Forbidden, CurrentPrincipal>,
  scopes: readonly string[],
  actor?: Caller["actor"]
) =>
  Effect.result(check).pipe(
    Effect.provideService(CurrentPrincipal, {
      subject: "owner",
      scopes,
      actor: actor ?? { kind: "client", clientId: "fixture" },
      expiresAt: undefined,
    })
  );

const unauthenticated = sent(
  new Action.Unauthenticated({ message: "Authentication required" })
);

const missingToken = sent(
  new Action.Unauthenticated({ message: "A bearer token is required." })
);

const stepUp = sent(
  new Action.Forbidden({
    message: "Requires notes:write.",
    scopes: ["notes:write"],
  })
);

it.effect(
  "requires refuses a caller without the scope, naming only that scope, and only to an OAuth client",
  () =>
    Effect.gen(function* () {
      assert.equal(
        (yield* decide(Notes.requires("notes:write"), ["notes:write"]))._tag,
        "Success"
      );

      const refused = yield* decide(Notes.requires("notes:write"), [
        "notes:read",
      ]);

      assert.equal(refused._tag, "Failure");
      assert.deepEqual(sent(refused.failure), stepUp);

      for (const actor of [
        { kind: "key", keyId: "key-1" },
        { kind: "local" },
      ] as const) {
        const other = yield* decide(
          Notes.requires("notes:write"),
          ["notes:read"],
          actor
        );

        assert.equal(other._tag, "Failure");
        assert.deepEqual(
          sent(other.failure),
          sent(new Action.Forbidden({ message: "Requires notes:write." }))
        );
      }

      assert.equal(
        (yield* decide(authorize(read), ["notes:read"]))._tag,
        "Success"
      );
      assert.equal(
        (yield* decide(authorize(write), ["notes:read"]))._tag,
        "Failure"
      );
    })
);

it.effect(
  "the process on a local surface holds every declared scope, and the application's rule admits it",
  () =>
    Effect.gen(function* () {
      const local = Notes.local("owner");

      assert.deepEqual(local, {
        subject: "owner",
        scopes: ["notes:read", "notes:write"],
        actor: { kind: "local" },
        expiresAt: undefined,
      });

      for (const action of [read, write]) {
        assert.equal(
          (yield* decide(authorize(action), local.scopes, local.actor))._tag,
          "Success"
        );
      }

      const single = Resource.make(Login, {
        scopes: ["notes:read"],
        required: "notes:read",
      });

      assert.deepEqual(single.local("owner").scopes, ["notes:read"]);
    })
);

it.live(
  "admission verifies outside a router and renders a ready-to-send refusal",
  () =>
    Effect.gen(function* () {
      const issuer = yield* startIssuer(`${publicUrl}/`);
      const resource = yield* resourceFor(issuer.issuer);

      const admit = (
        authorization: string | undefined,
        scope?: "notes:read" | "notes:write"
      ) => resource.admit(authorization, scope);

      const token = yield* Effect.promise(async () => await issuer.sign());
      const accepted = yield* admit(`Bearer ${token}`);
      assert.equal(accepted.ok, true);
      assert.equal(accepted.principal.subject, "owner");
      assert.equal(accepted.principal.actor.kind, "client");

      const claims = yield* Schema.decodeEffect(
        Schema.fromJsonString(Schema.Struct({ exp: Schema.Finite }))
      )(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());

      assert.equal(accepted.principal.expiresAt, claims.exp * 1000);

      const byKey = yield* admit(`Bearer ${issuer.key}`);
      assert.equal(byKey.ok, true);
      assert.equal(byKey.principal.expiresAt, undefined);

      const missing = yield* admit(undefined);
      assert.equal(missing.ok, false);
      assert.equal(missing.refusal.status, 401);
      assert.deepEqual(JSON.parse(missing.refusal.body), missingToken);

      assert.equal((yield* admit(`bearer ${issuer.key}`)).ok, true);

      const invalid = yield* admit("Bearer not-a-token");
      assert.equal(invalid.ok, false);
      assert.equal(invalid.refusal.status, 401);
      assert.deepEqual(JSON.parse(invalid.refusal.body), unauthenticated);

      const readOnly = yield* admit(
        `Bearer ${yield* Effect.promise(async () => await issuer.sign({ scope: "notes:read" }))}`,
        "notes:write"
      );

      assert.equal(readOnly.ok, false);
      assert.equal(readOnly.refusal.status, 403);
      assert.deepEqual(JSON.parse(readOnly.refusal.body), stepUp);

      const readOnlyKey = yield* admit(
        `Bearer ${issuer.readOnlyKey}`,
        "notes:write"
      );

      assert.equal(readOnlyKey.ok, false);
      assert.equal(readOnlyKey.refusal.status, 403);
      assert.deepEqual(
        JSON.parse(readOnlyKey.refusal.body),
        sent(new Action.Forbidden({ message: "Requires notes:write." }))
      );
      assert.equal(
        (yield* admit(`Bearer ${issuer.key}`, "notes:write")).ok,
        true
      );

      issuer.fail(503);
      assert.equal((yield* admit(`Bearer ${issuer.key}`)).ok, true);

      const cold = yield* resourceFor(issuer.issuer);
      const unavailable = yield* cold.admit(`Bearer ${issuer.key}`);
      assert.equal(unavailable.ok, false);
      assert.equal(unavailable.refusal.status, 503);

      const refusal: unknown = JSON.parse(unavailable.refusal.body);
      expect(refusal).toMatchObject({ _tag: "ProviderUnavailable" });
    })
);

it.live(
  "a WebSocket upgrade is admitted by key, or refused before it is upgraded",
  () =>
    Effect.gen(function* () {
      const issuer = yield* startIssuer(`${publicUrl}/`);
      const resource = yield* resourceFor(issuer.issuer);
      const services = yield* Effect.context();

      const answer = async (incoming: IncomingMessage, socket: Duplex) => {
        const admission = await Effect.runPromiseWith(services)(
          resource.admit(incoming.headers.authorization, "notes:write")
        );

        if (!admission.ok) {
          const { status, headers, body } = admission.refusal;

          const lines = Object.entries(headers).map(
            ([name, value]) => `${name}: ${value}`
          );

          socket.end(
            [`HTTP/1.1 ${status} Refused`, ...lines, "", body].join("\r\n")
          );

          return;
        }

        socket.end(
          "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        );
      };

      const server = yield* Effect.acquireRelease(
        Effect.sync(() =>
          createServer().on("upgrade", (incoming, socket) => {
            void answer(incoming, socket);
          })
        ),
        (opened) => Effect.sync(() => opened.close())
      );

      server.listen(0, "127.0.0.1");
      yield* Effect.promise(async () => {
        await once(server, "listening");
      });
      const address = server.address();

      if (address === null || !(address instanceof Object)) {
        throw new Error("No address");
      }

      const upgrade = (authorization: string) =>
        Effect.promise(async () => {
          const outgoing = request({
            host: "127.0.0.1",
            port: address.port,
            path: "/terminal",
            headers: {
              connection: "upgrade",
              upgrade: "websocket",
              authorization,
            },
          });

          outgoing.end();

          const [event, value] = await Promise.race([
            once(outgoing, "upgrade").then(([response, socket]: unknown[]) => {
              assert.ok(response instanceof IncomingMessage);
              assert.ok(socket instanceof Socket);

              return ["upgrade", { response, socket }] as const;
            }),
            once(outgoing, "response").then(([response]: unknown[]) => {
              assert.ok(response instanceof IncomingMessage);

              return ["response", { response }] as const;
            }),
          ]);

          if ("socket" in value) {
            value.socket.destroy();
          } else {
            value.response.resume();
          }

          return { event, status: value.response.statusCode };
        });

      assert.deepEqual(yield* upgrade(`Bearer ${issuer.key}`), {
        event: "upgrade",
        status: 101,
      });
      assert.deepEqual(yield* upgrade(`Bearer clankerauth_${"x".repeat(43)}`), {
        event: "response",
        status: 401,
      });
      assert.deepEqual(yield* upgrade(`Bearer ${issuer.readOnlyKey}`), {
        event: "response",
        status: 403,
      });
    })
);

it.live(
  "a resource that accepts only access tokens refuses a key by shape alone",
  () =>
    Effect.gen(function* () {
      const issuer = yield* startIssuer(`${publicUrl}/`);

      const resource = yield* withHttp(
        resourceOf({
          issuer: issuer.issuer,
          publicUrl: new URL(publicUrl),
          store: Verifier.store(),
          ...guarded,
          apiKeys: false,
        })
      );

      const refused = yield* resource.admit(`Bearer ${issuer.key}`);
      assert.equal(refused.ok, false);
      assert.equal(refused.refusal.status, 401);
      assert.deepEqual(JSON.parse(refused.refusal.body), unauthenticated);
      assert.equal(issuer.keyLists(), 0);

      const accepted = yield* resource.admit(
        `Bearer ${yield* Effect.promise(async () => await issuer.sign())}`
      );

      assert.equal(accepted.ok, true);
    })
);

it.live(
  "one resource at the origin root covers every surface an MCP client asks about",
  () =>
    Effect.gen(function* () {
      const issuer = yield* startIssuer(`${publicUrl}/`);

      const resource = yield* withHttp(
        resourceOf({
          issuer: issuer.issuer,
          publicUrl: new URL(`${publicUrl}/api?x=1`),
          store: Verifier.store(),
          ...guarded,
        })
      );

      assert.equal(resource.resource, `${publicUrl}/`);
      assert.equal(new URL(resource.resource).href, resource.resource);

      for (const endpoint of ["/mcp", "/api/notes/read", "/"]) {
        assert.equal(
          checkResourceAllowed({
            requestedResource: new URL(endpoint, publicUrl),
            configuredResource: resource.resource,
          }),
          true
        );
      }

      assert.equal(
        checkResourceAllowed({
          requestedResource: new URL("/mcp", "http://127.0.0.1:7338"),
          configuredResource: resource.resource,
        }),
        false
      );
    })
);

class Throttled extends Schema.TaggedError<
  Throttled,
  { readonly brand: unique symbol }
>()("Throttled", { message: Schema.String }, { httpApiStatus: 429 }) {}

describe("the types", () => {
  it("a resource's descriptor declares ProviderUnavailable, which the types require", () => {
    const declaration = { scopes: ["notes:read"], required: "notes:read" };

    Resource.make(
      // @ts-expect-error -- `error: ProviderUnavailable` is missing from the descriptor.
      Authentication.make("notes.Undeclared", CurrentPrincipal),
      declaration
    );

    Resource.make(
      // @ts-expect-error -- declaring another error instead does not declare it.
      Authentication.make("notes.Other", CurrentPrincipal, {
        error: Throttled,
      }),
      declaration
    );

    // why: always true, but only a `boolean` to the types, so neither branch is narrowed away.
    const declares: boolean = Math.random() < 2;

    Resource.make(
      // @ts-expect-error -- declaring it on one branch only does not declare it.
      Authentication.make("notes.Optional", CurrentPrincipal, {
        error: declares ? ProviderUnavailable : undefined,
      }),
      declaration
    );

    Resource.make(
      Authentication.make("notes.Union", CurrentPrincipal, {
        error: Schema.Union([ProviderUnavailable, Throttled]),
      }),
      declaration
    );

    const Declaring = Resource.make(
      Authentication.make("notes.Declaring", CurrentPrincipal, {
        error: [Throttled, ProviderUnavailable],
      }),
      declaration
    );

    const declared: ReadonlyArray<
      typeof Throttled | typeof ProviderUnavailable
    > = Declaring.authentication.error;

    assert.deepEqual(declared, [Throttled, ProviderUnavailable]);
  });

  it("a scope the resource does not declare is a type error wherever a scope is checked", () => {
    expectTypeOf(Notes.requires)
      .parameter(0)
      .toEqualTypeOf<"notes:read" | "notes:write">();

    // @ts-expect-error -- `notes:wirte` is none of the resource's scopes.
    void Notes.requires("notes:wirte");
    // @ts-expect-error -- nor here.
    void Notes.admitted("notes:wirte");

    const built = Effect.map(Notes.service, ({ admit, watch }) => {
      // @ts-expect-error -- nor for a caller outside the router.
      void admit(undefined, "notes:wirte");
      // @ts-expect-error -- nor for a connection held to it.
      void watch(undefined, "notes:wirte");

      return [admit(undefined, "notes:write"), watch(undefined, "notes:write")];
    });

    void [Notes.requires("notes:write"), Notes.admitted("notes:write"), built];
  });
});
