import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import { Effect, Schema } from "effect";
import { checkResourceAllowed } from "@modelcontextprotocol/client";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import { ConfigurationError, InsufficientScope, Unauthorized } from "../src/index.ts";
import { CurrentPrincipal, Resource } from "../src/effect-actions.ts";
import { publicUrl, startIssuer } from "./issuer.ts";
import { withHttp } from "./support.ts";

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

const resourceFor = (issuer: string, writeScope?: string) => {
  const base = {
    issuer,
    resource: `${publicUrl}/`,
    scopes: ["notes:read", "notes:write"],
    requiredScopes: ["notes:read"],
  };

  return Effect.runPromise(
    withHttp(Resource.make(writeScope === undefined ? base : { ...base, writeScope })),
  );
};

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
  const issuer = await startIssuer();

  try {
    const guarded = await resourceFor(issuer.issuer, "notes:write");

    assert.equal((await decide(guarded, read, ["notes:read"]))._tag, "Success");
    assert.equal((await decide(guarded, write, ["notes:read", "notes:write"]))._tag, "Success");

    const refused = await decide(guarded, write, ["notes:read"]);
    assert.equal(refused._tag, "Failure");
    assert.deepEqual(refused.failure, new InsufficientScope({ scope: "notes:write" }));
    assert.deepEqual(
      Schema.encodeSync(InsufficientScope)(refused.failure),
      Schema.encodeSync(InsufficientScope)(new InsufficientScope({ scope: "notes:write" })),
    );

    // A single-scope resource configures no write scope: verification is the policy.
    const single = await resourceFor(issuer.issuer);
    assert.equal((await decide(single, write, ["notes:read"]))._tag, "Success");
    assert.equal(single.writeScope, undefined);
  } finally {
    await issuer.close();
  }
});

test("admission verifies outside a router and renders a ready-to-send refusal", async () => {
  const issuer = await startIssuer();

  try {
    const resource = await resourceFor(issuer.issuer, "notes:write");

    const admit = (authorization?: string, access?: Action.Access) =>
      Effect.runPromise(resource.admit(authorization, access));

    const token = await issuer.sign({}, "");
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
    const missing = await admit();
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

    issuer.fail(429);
    const limited = await admit(`Bearer ${issuer.key}`);
    assert.equal(limited.ok, false);
    assert.equal(limited.refusal.status, 429);
    assert.equal(limited.refusal.headers["retry-after"], "60");
    assert.equal(limited.refusal.headers["www-authenticate"], undefined);

    issuer.fail(503);
    const unavailable = await admit(`Bearer ${issuer.key}`);
    assert.equal(unavailable.ok, false);
    assert.equal(unavailable.refusal.status, 503);
  } finally {
    await issuer.close();
  }
});

test("one resource at the origin root covers every surface an MCP client asks about", async () => {
  const issuer = await startIssuer();

  try {
    const resource = await resourceFor(issuer.issuer);

    // RFC 9728: a resource with no path is published at the bare well-known path.
    assert.equal(
      resource.discovery.metadataUrl,
      `${publicUrl}/.well-known/oauth-protected-resource`,
    );
    assert.match(resource.challenge()["www-authenticate"], /resource_metadata=/u);

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

    assert.equal(new URL(resource.resource).href, resource.resource);

    // An identifier the client would rewrite is refused at construction.
    const failure = await Effect.runPromise(
      Effect.flip(
        withHttp(Resource.make({ issuer: issuer.issuer, resource: publicUrl, scopes: [] })),
      ),
    );

    assert(failure instanceof ConfigurationError);
    assert.match(failure.message, /canonical/u);
  } finally {
    await issuer.close();
  }
});
