import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import { once } from "node:events";
import { test } from "vite-plus/test";
import { Effect, Schema } from "effect";
import { checkResourceAllowed } from "@modelcontextprotocol/client";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { Resource } from "../src/effect-actions.ts";
import { ProviderUnavailable } from "../src/errors.ts";
import { CurrentPrincipal, type Caller } from "../src/session.ts";
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

/** The tests' scopes: a read every credential carries, and a write the application requires. */
const guarded = { scopes: ["notes:read", "notes:write"], required: "notes:read" } as const;

const resourceFor = (issuer: string) =>
  Effect.runPromise(withHttp(resourceOf({ issuer, publicUrl: new URL(publicUrl), ...guarded })));

const decide = (
  check: Effect.Effect<void, Action.Forbidden, CurrentPrincipal>,
  scopes: ReadonlyArray<string>,
  actor: Caller["actor"] = { kind: "client", clientId: "fixture" },
) =>
  Effect.runPromise(
    Effect.result(check).pipe(
      Effect.provideService(CurrentPrincipal, {
        subject: "owner",
        scopes,
        actor,
        expiresAt: undefined,
      }),
    ),
  );

const unauthenticated = sent(new Action.Unauthenticated({ message: "Authentication required" }));

// No credential at all, refused as effect-actions refuses a route without one.
const missingToken = sent(new Action.Unauthenticated({ message: "A bearer token is required." }));

const stepUp = sent(
  new Action.Forbidden({ message: "Requires notes:write.", scopes: ["notes:write"] }),
);

test("requires refuses a caller without the scope, and names only that scope", async () => {
  assert.equal((await decide(Notes.requires("notes:write"), ["notes:write"]))._tag, "Success");

  const refused = await decide(Notes.requires("notes:write"), ["notes:read"]);
  assert.equal(refused._tag, "Failure");
  // The built-in refusal every surface declares, on which an OAuth client steps up.
  assert.deepEqual(sent(refused.failure), stepUp);

  // Only an OAuth client can re-authorize, so any other refusal names no scope to step up to.
  for (const actor of [{ kind: "key", keyId: "key-1" }, { kind: "local" }] as const) {
    const other = await decide(Notes.requires("notes:write"), ["notes:read"], actor);
    assert.equal(other._tag, "Failure");
    assert.deepEqual(
      sent(other.failure),
      sent(new Action.Forbidden({ message: "Requires notes:write." })),
    );
  }

  // The application's rule decides which actions need it.
  assert.equal((await decide(authorize(read), ["notes:read"]))._tag, "Success");
  assert.equal((await decide(authorize(write), ["notes:read"]))._tag, "Failure");
});

test("the process on a local surface holds every declared scope, and the application's rule admits it", async () => {
  const local = Notes.local("owner");

  assert.deepEqual(local, {
    subject: "owner",
    scopes: ["notes:read", "notes:write"],
    actor: { kind: "local" },
    expiresAt: undefined,
  });

  for (const action of [read, write])
    assert.equal((await decide(authorize(action), local.scopes, local.actor))._tag, "Success");

  const single = Resource.make(Login, { scopes: ["notes:read"], required: "notes:read" });
  assert.deepEqual(single.local("owner").scopes, ["notes:read"]);
});

test("admission verifies outside a router and renders a ready-to-send refusal", async () => {
  const issuer = await startIssuer(`${publicUrl}/`);

  try {
    const resource = await resourceFor(issuer.issuer);

    const admit = (authorization: string | undefined, scope?: "notes:read" | "notes:write") =>
      Effect.runPromise(resource.admit(authorization, scope));

    const token = await issuer.sign();
    const accepted = await admit(`Bearer ${token}`);
    assert.equal(accepted.ok, true);
    assert.equal(accepted.principal.subject, "owner");
    assert.equal(accepted.principal.actor.kind, "client");

    // The verified `exp`, so a host bounding a connection never decodes the token again.
    const claims = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());
    assert.equal(accepted.principal.expiresAt, claims.exp * 1000);

    const byKey = await admit(`Bearer ${issuer.key}`);
    assert.equal(byKey.ok, true);
    assert.equal(byKey.principal.expiresAt, undefined);

    const missing = await admit(undefined);
    assert.equal(missing.ok, false);
    assert.equal(missing.refusal.status, 401);
    assert.deepEqual(JSON.parse(missing.refusal.body), missingToken);

    // The header is read through effect-actions, as a route reads a request's.
    assert.equal((await admit(`bearer ${issuer.key}`)).ok, true);

    const invalid = await admit("Bearer not-a-token");
    assert.equal(invalid.ok, false);
    assert.equal(invalid.refusal.status, 401);
    assert.deepEqual(JSON.parse(invalid.refusal.body), unauthenticated);

    // A socket may demand the write scope before it is established.
    const readOnly = await admit(
      `Bearer ${await issuer.sign({ scope: "notes:read" })}`,
      "notes:write",
    );

    assert.equal(readOnly.ok, false);
    assert.equal(readOnly.refusal.status, 403);
    assert.deepEqual(JSON.parse(readOnly.refusal.body), stepUp);

    // A key cannot step up: a plain 403, naming no scope that would prompt a login.
    const readOnlyKey = await admit(`Bearer ${issuer.readOnlyKey}`, "notes:write");
    assert.equal(readOnlyKey.ok, false);
    assert.equal(readOnlyKey.refusal.status, 403);
    assert.deepEqual(
      JSON.parse(readOnlyKey.refusal.body),
      sent(new Action.Forbidden({ message: "Requires notes:write." })),
    );
    assert.equal((await admit(`Bearer ${issuer.key}`, "notes:write")).ok, true);

    // An outage after the key list was read is no refusal at all.
    issuer.fail(503);
    assert.equal((await admit(`Bearer ${issuer.key}`)).ok, true);

    // Before any list, a key cannot be decided: the SDK's 503, not a refusal.
    const cold = await resourceFor(issuer.issuer);
    const unavailable = await Effect.runPromise(cold.admit(`Bearer ${issuer.key}`));
    assert.equal(unavailable.ok, false);
    assert.equal(unavailable.refusal.status, 503);
    assert.equal(JSON.parse(unavailable.refusal.body)._tag, "ProviderUnavailable");
  } finally {
    await issuer.close();
  }
});

test("a WebSocket upgrade is admitted by key, or refused before it is upgraded", async () => {
  const issuer = await startIssuer(`${publicUrl}/`);
  const resource = await resourceFor(issuer.issuer);

  // A Node upgrade handler: the socket is switched only after admission.
  const server = createServer().on("upgrade", async (incoming, socket) => {
    const admission = await Effect.runPromise(
      resource.admit(incoming.headers.authorization, "notes:write"),
    );

    if (!admission.ok) {
      const { status, headers, body } = admission.refusal;
      const lines = Object.entries(headers).map(([name, value]) => `${name}: ${value}`);
      socket.end([`HTTP/1.1 ${status} Refused`, ...lines, "", body].join("\r\n"));

      return;
    }

    socket.end(
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    );
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();

  if (address === null || !(address instanceof Object)) throw new Error("No address");

  const upgrade = async (authorization: string) => {
    const outgoing = request({
      host: "127.0.0.1",
      port: address.port,
      path: "/terminal",
      headers: { connection: "upgrade", upgrade: "websocket", authorization },
    });

    outgoing.end();

    const [event, value] = await Promise.race([
      once(outgoing, "upgrade").then(
        ([response, socket]) => ["upgrade", { response, socket }] as const,
      ),
      once(outgoing, "response").then(([response]) => ["response", { response }] as const),
    ]);

    if ("socket" in value) value.socket.destroy();
    else value.response.resume();

    return { event, status: value.response.statusCode };
  };

  try {
    assert.deepEqual(await upgrade(`Bearer ${issuer.key}`), { event: "upgrade", status: 101 });
    assert.deepEqual(await upgrade(`Bearer clankerauth_${"x".repeat(43)}`), {
      event: "response",
      status: 401,
    });
    // Admitted for writing, so a read-only key is refused before the socket switches.
    assert.deepEqual(await upgrade(`Bearer ${issuer.readOnlyKey}`), {
      event: "response",
      status: 403,
    });
  } finally {
    server.close();
    await issuer.close();
  }
});

test("a resource that accepts only access tokens refuses a key by shape alone", async () => {
  const issuer = await startIssuer(`${publicUrl}/`);

  try {
    const resource = await Effect.runPromise(
      withHttp(
        resourceOf({
          issuer: issuer.issuer,
          publicUrl: new URL(publicUrl),
          ...guarded,
          apiKeys: false,
        }),
      ),
    );

    const refused = await Effect.runPromise(resource.admit(`Bearer ${issuer.key}`));
    assert.equal(refused.ok, false);
    assert.equal(refused.refusal.status, 401);
    assert.deepEqual(JSON.parse(refused.refusal.body), unauthenticated);
    // The issuer would have accepted this key. It was never asked: the prefix decides.
    assert.equal(issuer.keyLists(), 0);

    // Access tokens still verify, which is the only credential such a resource takes.
    const accepted = await Effect.runPromise(resource.admit(`Bearer ${await issuer.sign()}`));

    assert.equal(accepted.ok, true);
  } finally {
    await issuer.close();
  }
});

test("one resource at the origin root covers every surface an MCP client asks about", async () => {
  const issuer = await startIssuer(`${publicUrl}/`);

  try {
    // Any path on the public URL is discarded: the resource is the origin root.
    const resource = await Effect.runPromise(
      withHttp(
        resourceOf({
          issuer: issuer.issuer,
          publicUrl: new URL(`${publicUrl}/api?x=1`),
          ...guarded,
        }),
      ),
    );

    assert.equal(resource.resource, `${publicUrl}/`);
    assert.equal(new URL(resource.resource).href, resource.resource);

    // The official client accepts an origin-root resource for any endpoint under it,
    // and sends back exactly the identifier the metadata published.
    for (const endpoint of ["/mcp", "/api/notes/read", "/"]) {
      assert.equal(
        checkResourceAllowed({
          requestedResource: new URL(endpoint, publicUrl),
          configuredResource: resource.resource,
        }),
        true,
      );
    }

    assert.equal(
      checkResourceAllowed({
        requestedResource: new URL("/mcp", "http://127.0.0.1:7338"),
        configuredResource: resource.resource,
      }),
      false,
    );
  } finally {
    await issuer.close();
  }
});

/** An error of the application's own, which a descriptor may declare beside the SDK's. */
class Throttled extends Schema.TaggedError<Throttled>()(
  "Throttled",
  { message: Schema.String },
  { httpApiStatus: 429 },
) {}

test("a resource's descriptor declares ProviderUnavailable, which the types require", () => {
  const declaration = { scopes: ["notes:read"], required: "notes:read" };

  // The verifier fails with `ProviderUnavailable` when the issuer cannot be reached, so a
  // descriptor that does not declare it is refused where the resource is declared.
  // @ts-expect-error -- `error: ProviderUnavailable` is missing from the descriptor.
  Resource.make(Authentication.make("notes.Undeclared", CurrentPrincipal), declaration);

  Resource.make(
    // @ts-expect-error -- declaring another error instead does not declare it.
    Authentication.make("notes.Other", CurrentPrincipal, { error: Throttled }),
    declaration,
  );

  // A descriptor that only may declare it does not: without it, an outage would be a defect.
  // `declares` is always true here, but only a `boolean` to the types.
  const declares: boolean = Math.random() < 2;

  Resource.make(
    // @ts-expect-error -- declaring it on one branch only does not declare it.
    Authentication.make("notes.Optional", CurrentPrincipal, {
      error: declares ? ProviderUnavailable : undefined,
    }),
    declaration,
  );

  // A union schema holding it declares it, as its decoding does.
  Resource.make(
    Authentication.make("notes.Union", CurrentPrincipal, {
      error: Schema.Union([ProviderUnavailable, Throttled]),
    }),
    declaration,
  );

  // A descriptor may declare more, which the resource keeps as it was given.
  const Declaring = Resource.make(
    Authentication.make("notes.Declaring", CurrentPrincipal, {
      error: [Throttled, ProviderUnavailable],
    }),
    declaration,
  );

  const declared: ReadonlyArray<typeof Throttled | typeof ProviderUnavailable> =
    Declaring.authentication.error;

  assert.deepEqual(declared, [Throttled, ProviderUnavailable]);
});

test("a scope the resource does not declare is a type error wherever a scope is checked", () => {
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
