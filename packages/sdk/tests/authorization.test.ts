import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import { once } from "node:events";
import { test } from "vite-plus/test";
import { Effect, Schema } from "effect";
import { checkResourceAllowed } from "@modelcontextprotocol/client";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import { InsufficientScope, Unauthorized } from "../src/errors.ts";
import { CurrentPrincipal, Resource } from "../src/effect-actions.ts";
import { publicUrl, startIssuer, withHttp } from "./support.ts";

const read = Action.make("read", {
  description: "Read",
  access: "read",
  success: Schema.String,
});

const write = Action.make("write", {
  description: "Write",
  access: "write",
  success: Schema.String,
});

const resourceFor = (issuer: string, scopes: Resource.Scopes) =>
  Effect.runPromise(withHttp(Resource.make({ issuer, publicUrl: new URL(publicUrl), scopes })));

const guarded = { read: "notes:read", write: "notes:write" } as const;

const decide = (resource: Resource.Resource, action: Action.Any, scopes: ReadonlyArray<string>) =>
  Effect.runPromise(
    Effect.result(resource.authorize(action)).pipe(
      Effect.provideService(CurrentPrincipal, {
        subject: "owner",
        scopes,
        actor: { kind: "client", clientId: "fixture" },
        expiresAt: undefined,
      }),
    ),
  );

test("the pre-handler hook refuses only writes, and names only the missing scope", async () => {
  const issuer = await startIssuer(`${publicUrl}/`);

  try {
    const resource = await resourceFor(issuer.issuer, guarded);

    assert.equal((await decide(resource, read, ["notes:read"]))._tag, "Success");
    assert.equal((await decide(resource, write, ["notes:read", "notes:write"]))._tag, "Success");

    const refused = await decide(resource, write, ["notes:read"]);
    assert.equal(refused._tag, "Failure");
    assert.deepEqual(refused.failure, new InsufficientScope({ scope: "notes:write" }));
    assert.deepEqual(
      Schema.encodeSync(InsufficientScope)(refused.failure),
      Schema.encodeSync(InsufficientScope)(new InsufficientScope({ scope: "notes:write" })),
    );

    // A single-scope application names only `read`: verification is the whole policy.
    const single = await resourceFor(issuer.issuer, { read: "notes:read" });
    assert.equal((await decide(single, write, ["notes:read"]))._tag, "Success");
  } finally {
    await issuer.close();
  }
});

test("admission verifies outside a router and renders a ready-to-send refusal", async () => {
  const issuer = await startIssuer(`${publicUrl}/`);

  try {
    const resource = await resourceFor(issuer.issuer, guarded);

    const admit = (authorization: string | undefined, access: Action.Access = "read") =>
      Effect.runPromise(resource.admit(authorization, access));

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

    // RFC 6750 §3.1: no credential, no error code.
    const missing = await admit(undefined);
    assert.equal(missing.ok, false);
    assert.equal(missing.refusal.status, 401);
    assert.equal(missing.refusal.headers["cache-control"], "no-store");
    assert.equal(missing.refusal.headers["content-type"], "application/json");
    assert.doesNotMatch(missing.refusal.headers["www-authenticate"] ?? "", /error=/u);
    assert.deepEqual(
      JSON.parse(missing.refusal.body),
      Schema.encodeSync(Unauthorized)(new Unauthorized({ message: "Authentication required" })),
    );

    const invalid = await admit("Bearer not-a-token");
    assert.equal(invalid.ok, false);
    assert.equal(invalid.refusal.status, 401);
    assert.match(invalid.refusal.headers["www-authenticate"] ?? "", /error="invalid_token"/u);

    // A socket may demand the write scope before it is established.
    const readOnly = await admit(`Bearer ${issuer.readOnlyKey}`, "write");
    assert.equal(readOnly.ok, false);
    assert.equal(readOnly.refusal.status, 403);
    assert.deepEqual(
      JSON.parse(readOnly.refusal.body),
      Schema.encodeSync(InsufficientScope)(new InsufficientScope({ scope: "notes:write" })),
    );
    assert.match(readOnly.refusal.headers["www-authenticate"] ?? "", /error="insufficient_scope"/u);
    assert.match(readOnly.refusal.headers["www-authenticate"] ?? "", /scope="notes:write"/u);
    assert.equal((await admit(`Bearer ${issuer.key}`, "write")).ok, true);

    // An outage after the key list was read is no refusal at all.
    issuer.fail(503);
    assert.equal((await admit(`Bearer ${issuer.key}`)).ok, true);

    // Before any list, a key cannot be decided; that refusal carries no challenge.
    const cold = await resourceFor(issuer.issuer, guarded);
    const unavailable = await Effect.runPromise(cold.admit(`Bearer ${issuer.key}`, "read"));
    assert.equal(unavailable.ok, false);
    assert.equal(unavailable.refusal.status, 503);
    assert.equal(unavailable.refusal.headers["www-authenticate"], undefined);
  } finally {
    await issuer.close();
  }
});

test("a WebSocket upgrade is admitted by key, or refused before it is upgraded", async () => {
  const issuer = await startIssuer(`${publicUrl}/`);
  const resource = await resourceFor(issuer.issuer, guarded);

  // A Node upgrade handler: the socket is switched only after admission.
  const server = createServer().on("upgrade", async (incoming, socket) => {
    const admission = await Effect.runPromise(
      resource.admit(incoming.headers.authorization, "write"),
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
        Resource.make({
          issuer: issuer.issuer,
          publicUrl: new URL(publicUrl),
          scopes: guarded,
          apiKeys: false,
        }),
      ),
    );

    const refused = await Effect.runPromise(resource.admit(`Bearer ${issuer.key}`, "read"));
    assert.equal(refused.ok, false);
    assert.equal(refused.refusal.status, 401);
    assert.deepEqual(
      JSON.parse(refused.refusal.body),
      Schema.encodeSync(Unauthorized)(new Unauthorized({ message: "Authentication required" })),
    );
    // The issuer would have accepted this key. It was never asked: the prefix decides.
    assert.equal(issuer.keyLists(), 0);

    // Access tokens still verify, which is the only credential such a resource takes.
    const accepted = await Effect.runPromise(
      resource.admit(`Bearer ${await issuer.sign()}`, "read"),
    );

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
        Resource.make({
          issuer: issuer.issuer,
          publicUrl: new URL(`${publicUrl}/api?x=1`),
          scopes: guarded,
        }),
      ),
    );

    assert.equal(resource.resource, `${publicUrl}/`);
    assert.equal(new URL(resource.resource).href, resource.resource);

    // RFC 9728: a resource with no path is published at the bare well-known path.
    assert.equal(
      resource.discovery.metadataUrl,
      `${publicUrl}/.well-known/oauth-protected-resource`,
    );

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
