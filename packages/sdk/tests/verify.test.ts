import assert from "node:assert/strict";
import type { JWTPayload } from "jose";
import { test } from "vite-plus/test";
import { Effect } from "effect";
import { Verifier } from "../src/index.ts";
import {
  ConfigurationError,
  InsufficientScope,
  ProviderUnavailable,
  Unauthorized,
} from "../src/errors.ts";
import { publicUrl, startIssuer, withHttp } from "./support.ts";

const resource = `${publicUrl}/api`;

type Issuer = Awaited<ReturnType<typeof startIssuer>>;

const verifierFor = (issuer: Issuer, target = resource) =>
  Effect.runPromise(
    withHttp(
      Verifier.make({ issuer: issuer.issuer, resource: target, requiredScopes: ["notes:read"] }),
    ),
  );

const withIssuer = async (body: (verifier: Verifier.Verifier, issuer: Issuer) => Promise<void>) => {
  const issuer = await startIssuer(resource);

  try {
    await body(await verifierFor(issuer), issuer);
  } finally {
    await issuer.close();
  }
};

const failure = <A, E>(effect: Effect.Effect<A, E>) => Effect.runPromise(Effect.flip(effect));

test("API keys verify offline against one key list, with their actor, scopes and expiry", () =>
  withIssuer(async (verifier, issuer) => {
    const principal = await Effect.runPromise(verifier.verify(`Bearer ${issuer.key}`));
    assert.equal(principal.subject, "owner");
    assert.deepEqual(principal.actor, { kind: "key", keyId: "key-1" });
    assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
    assert.equal(principal.expiresAt, undefined);
    assert.deepEqual((await Effect.runPromise(verifier.verifyToken(issuer.readOnlyKey))).scopes, [
      "notes:read",
    ]);
    // An unknown key has no entry to find: refused from the list already read.
    assert(
      (await failure(verifier.verifyToken(`clankerauth_${"x".repeat(43)}`))) instanceof
        Unauthorized,
    );
    assert.equal(issuer.keyLists(), 1);

    // Revocation reaches a verifier with its next list; a new one reads it now.
    issuer.revoke(issuer.key);
    await Effect.runPromise(verifier.verifyToken(issuer.key));
    assert(
      (await failure((await verifierFor(issuer)).verifyToken(issuer.key))) instanceof Unauthorized,
    );

    const expiresAt = new Date(Date.now() + 60_000);
    const expiring = issuer.apiKey(undefined, expiresAt);
    const listed = await verifierFor(issuer);
    assert.equal(
      (await Effect.runPromise(listed.verifyToken(expiring))).expiresAt,
      expiresAt.getTime(),
    );

    // One key reaches several resources, with each resource's own scopes.
    const reports = "https://reports.internal/api";

    const both = issuer.apiKey({
      [resource]: ["notes:write", "notes:read"],
      [reports]: ["notes:read"],
    });

    const elsewhere = await verifierFor(issuer, reports);
    assert.deepEqual((await Effect.runPromise(elsewhere.verifyToken(both))).scopes, ["notes:read"]);

    // A key with no grant on a resource is not that resource's credential at all.
    assert((await failure(elsewhere.verifyToken(issuer.readOnlyKey))) instanceof Unauthorized);
  }));

test("JWTs bind exact issuer, audience, claims, lifetime and required scopes", () =>
  withIssuer(async (verifier, issuer) => {
    const token = await issuer.sign();
    const principal = await Effect.runPromise(verifier.verify(`Bearer ${token}`));
    assert.deepEqual(principal.actor, { kind: "client", clientId: "fixture" });
    assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
    assert.equal(issuer.keyLists(), 0);

    const other = await Effect.runPromise(
      withHttp(Verifier.make({ issuer: issuer.issuer, resource: `${publicUrl}/mcp` })),
    );

    assert((await failure(other.verifyToken(token))) instanceof Unauthorized);

    const claims: JWTPayload[] = [
      { iss: "https://evil.example/api/auth" },
      { aud: "http://another.example/api" },
      { exp: 0 },
      { cnf: { jkt: "proof" } },
      { client_id: undefined },
      { sub: "" },
      { scope: undefined },
      { iat: undefined },
    ];

    for (const claim of claims)
      assert(
        (await failure(verifier.verifyToken(await issuer.sign(claim)))) instanceof Unauthorized,
      );
    assert(
      (await failure(verifier.verifyToken(await issuer.sign({}, "JWT")))) instanceof Unauthorized,
    );
    await Effect.runPromise(
      verifier.verifyToken(await issuer.sign({ aud: [resource, "https://reports.internal/api"] })),
    );
    // A missing required scope is the one 403: it names only the scope that is missing.
    assert.deepEqual(
      await failure(verifier.verifyToken(await issuer.sign({ scope: "notes:write" }))),
      new InsufficientScope({ scope: "notes:read" }),
    );
  }));

test("malformed credentials and outages remain distinct typed outcomes", () =>
  withIssuer(async (verifier, issuer) => {
    for (const header of [
      null,
      "Bearer invalid, Bearer another",
      "Bearer not.a.jwt",
      "Bearer eyJhbGciOiJIUzI1NiJ9.e30.AA",
      // A token that does not name its key is refused before any key lookup.
      `Bearer ${Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "at+jwt" })).toString("base64url")}.e30.AA`,
    ])
      assert((await failure(verifier.verify(header))) instanceof Unauthorized);
    assert.equal(issuer.keyLists(), 0);
    // Before any list is read, an unreachable issuer leaves a key undecided.
    issuer.fail(503);
    assert((await failure(verifier.verifyToken(issuer.key))) instanceof ProviderUnavailable);
    assert(
      (await failure(verifier.verifyToken(await issuer.sign()))) instanceof ProviderUnavailable,
    );
  }));

test("invalid standalone verifier configuration fails at construction", async () => {
  const error = await Effect.runPromise(
    Effect.flip(withHttp(Verifier.make({ issuer: "not a URL", resource }))),
  );

  assert(error instanceof ConfigurationError);
});

test("the fake issuer rejects malformed key list requests", async () => {
  const issuer = await startIssuer(resource);

  try {
    for (const body of ["invalid", "{}", "[]", "null", '{"resource":42}']) {
      const response = await fetch(new URL("/api/issuer/keyList", issuer.issuer), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });

      assert.equal(response.status, 400);
      await response.body?.cancel();
    }
  } finally {
    await issuer.close();
  }
});
