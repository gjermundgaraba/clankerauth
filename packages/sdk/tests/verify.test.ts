import assert from "node:assert/strict";
import type { JWTPayload } from "jose";
import { test } from "vite-plus/test";
import { Effect } from "effect";
import {
  Verifier,
  Unauthorized,
  Forbidden,
  ProviderUnavailable,
  RateLimited,
  ConfigurationError,
} from "../src/index.ts";
import { publicUrl, startIssuer } from "./issuer.ts";
import { withHttp } from "./support.ts";

const resource = `${publicUrl}/api`;

const withIssuer = async (
  body: (
    verifier: Verifier.Verifier,
    issuer: Awaited<ReturnType<typeof startIssuer>>,
  ) => Promise<void>,
) => {
  const issuer = await startIssuer();

  try {
    await body(
      await Effect.runPromise(
        withHttp(
          Verifier.make({
            issuer: issuer.issuer,
            resource,
            requiredScopes: ["notes:read"],
          }),
        ),
      ),
      issuer,
    );
  } finally {
    await issuer.close();
  }
};

const failure = <A, E>(effect: Effect.Effect<A, E>) => Effect.runPromise(Effect.flip(effect));

test("API keys verify on every request, carry the actor, and observe revocation", () =>
  withIssuer(async (verifier, issuer) => {
    const principal = await Effect.runPromise(verifier.verify(`Bearer ${issuer.key}`));
    assert.equal(principal.subject, "owner");
    assert.deepEqual(principal.actor, { kind: "key", keyId: "writer" });
    assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
    assert.equal(issuer.count(), 1);
    assert.deepEqual((await Effect.runPromise(verifier.verifyToken(issuer.readOnlyKey))).scopes, [
      "notes:read",
    ]);
    issuer.keys.delete(issuer.key);
    assert((await failure(verifier.verifyToken(issuer.key))) instanceof Unauthorized);
    assert.equal(issuer.count(), 3);
  }));

test("JWTs bind exact issuer, audience, claims, lifetime and required scopes", () =>
  withIssuer(async (verifier, issuer) => {
    const token = await issuer.sign();
    const principal = await Effect.runPromise(verifier.verify(`Bearer ${token}`));
    assert.deepEqual(principal.actor, { kind: "client", clientId: "fixture" });
    assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
    assert.equal(issuer.count(), 0);

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
    ];

    for (const claim of claims)
      assert(
        (await failure(verifier.verifyToken(await issuer.sign(claim)))) instanceof Unauthorized,
      );
    assert(
      (await failure(verifier.verifyToken(await issuer.sign({}, "api", "JWT")))) instanceof
        Unauthorized,
    );
    await Effect.runPromise(
      verifier.verifyToken(await issuer.sign({ aud: [resource, "https://reports.internal/api"] })),
    );
    assert(
      (await failure(verifier.verifyToken(await issuer.sign({ scope: "notes:write" })))) instanceof
        Forbidden,
    );
  }));

test("malformed credentials, outages and rate limits remain distinct typed outcomes", () =>
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
    assert.equal(issuer.count(), 0);
    issuer.fail(503);
    assert((await failure(verifier.verifyToken(issuer.key))) instanceof ProviderUnavailable);
    assert(
      (await failure(verifier.verifyToken(await issuer.sign()))) instanceof ProviderUnavailable,
    );
    issuer.fail(429);
    assert((await failure(verifier.verifyToken(issuer.key))) instanceof RateLimited);
    issuer.fail(403);
    assert((await failure(verifier.verifyToken(issuer.key))) instanceof Forbidden);
    issuer.fail(undefined);
    issuer.malform(true);
    assert((await failure(verifier.verifyToken(issuer.key))) instanceof ProviderUnavailable);
  }));

test("invalid standalone verifier configuration fails at construction", async () => {
  const error = await Effect.runPromise(
    Effect.flip(withHttp(Verifier.make({ issuer: "not a URL", resource }))),
  );

  assert(error instanceof ConfigurationError);
});

test("issuer fixture rejects malformed API-key verification requests", async () => {
  const issuer = await startIssuer();

  try {
    for (const body of ["invalid", "{}", "[]", "null", '{"resource":42}']) {
      const response = await fetch(new URL("/api/issuer/verifyApiKey", issuer.issuer), {
        method: "POST",
        headers: { authorization: `Bearer ${issuer.key}`, "content-type": "application/json" },
        body,
      });

      assert.equal(response.status, 400);
      await response.body?.cancel();
    }
  } finally {
    await issuer.close();
  }
});
