import assert from "node:assert/strict";
import type { JWTPayload } from "jose";
import { test } from "vite-plus/test";
import {
  AuthError,
  IssuerResponseError,
  createVerifier,
  failureResponse,
  protectedResourceMetadata,
} from "../src/index.ts";
import { publicUrl, startIssuer } from "./issuer.ts";

const resource = `${publicUrl}/api`;
const withIssuer = async (
  body: (
    verifier: ReturnType<typeof createVerifier>,
    issuer: Awaited<ReturnType<typeof startIssuer>>,
    failures: string[],
  ) => Promise<void>,
) => {
  const issuer = await startIssuer();
  const failures: string[] = [];
  try {
    await body(
      createVerifier({
        issuer: issuer.issuer,
        resource,
        requiredScopes: ["notes:read"],
        onFailure: (operation, error) => {
          failures.push(
            error instanceof IssuerResponseError ? `${operation}:${error.status}` : operation,
          );
        },
      }),
      issuer,
      failures,
    );
  } finally {
    await issuer.close();
  }
};
const code = async (action: Promise<unknown>) => {
  try {
    await action;
  } catch (error) {
    assert(error instanceof AuthError, String(error));
    return error.code;
  }
  assert.fail("expected an AuthError");
};

test("API keys verify online on every request, carry the key as actor, and observe revocation", () =>
  withIssuer(async (verifier, issuer) => {
    const principal = await verifier.verify(`Bearer ${issuer.key}`);
    assert.equal(principal.subject, "owner");
    assert.deepEqual(principal.actor, { kind: "key", keyId: "writer" });
    assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
    assert.equal(issuer.count(), 1);
    const reader = await verifier.verifyToken(issuer.readOnlyKey);
    assert.deepEqual(reader.scopes, ["notes:read"]);
    issuer.keys.delete(issuer.key);
    assert.equal(await code(verifier.verify(`Bearer ${issuer.key}`)), "unauthorized");
    assert.equal(issuer.count(), 3);
  }));

test("JWTs bind exact issuer, audience, claims, lifetime and required scopes", () =>
  withIssuer(async (verifier, issuer) => {
    const token = await issuer.sign();
    const principal = await verifier.verify(`Bearer ${token}`);
    assert.deepEqual(principal.actor, { kind: "client", clientId: "fixture" });
    assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
    assert.equal(issuer.count(), 0);
    const other = createVerifier({ issuer: issuer.issuer, resource: `${publicUrl}/mcp` });
    assert.equal(await code(other.verifyToken(token)), "unauthorized");
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
      assert.equal(await code(verifier.verifyToken(await issuer.sign(claim))), "unauthorized");
    assert.equal(
      await code(verifier.verifyToken(await issuer.sign({}, "api", "JWT"))),
      "unauthorized",
    );
    await verifier.verifyToken(
      await issuer.sign({ aud: [resource, `${issuer.issuer}/oauth2/userinfo`] }),
    );
    assert.equal(
      await code(verifier.verifyToken(await issuer.sign({ scope: "notes:write" }))),
      "forbidden",
    );
  }));

test("malformed credentials, outages and rate limits are distinct outcomes", () =>
  withIssuer(async (verifier, issuer, failures) => {
    assert.equal(await code(verifier.verify(null)), "unauthorized");
    assert.equal(await code(verifier.verify("Bearer invalid, Bearer another")), "unauthorized");
    assert.equal(await code(verifier.verify("Bearer not.a.jwt")), "unauthorized");
    assert.equal(await code(verifier.verify("Bearer eyJhbGciOiJIUzI1NiJ9.e30.AA")), "unauthorized");
    assert.equal(issuer.count(), 0);
    assert.deepEqual(failures, []);
    issuer.fail(503);
    assert.equal(await code(verifier.verify(`Bearer ${issuer.key}`)), "unavailable");
    assert.equal(await code(verifier.verify(`Bearer ${await issuer.sign()}`)), "unavailable");
    assert.deepEqual(failures, ["api-key.verify:503", "jwt.verify"]);
    issuer.fail(429);
    assert.equal(await code(verifier.verify(`Bearer ${issuer.key}`)), "rate_limited");
    issuer.fail(403);
    assert.equal(await code(verifier.verify(`Bearer ${issuer.key}`)), "forbidden");
    issuer.fail(undefined);
    issuer.malform(true);
    assert.equal(await code(verifier.verify(`Bearer ${issuer.key}`)), "unavailable");
    assert.equal(failures.at(-1), "api-key.response");
  }));

test("failure responses carry discovery challenges and metadata names the issuer", async () => {
  const options = { resource, scopes: ["notes:read", "notes:write"] };
  const missing = failureResponse(new AuthError("unauthorized"), options);
  assert.equal(missing.status, 401);
  assert.equal(
    missing.headers.get("www-authenticate"),
    `Bearer resource_metadata="${publicUrl}/.well-known/oauth-protected-resource/api", error="invalid_token", scope="notes:read notes:write"`,
  );
  assert.deepEqual(await missing.json(), {
    error: "unauthorized",
    error_description: "Authentication required",
  });
  const forbidden = failureResponse(new AuthError("forbidden"), {
    ...options,
    scopes: ["notes:write"],
  });
  assert.equal(forbidden.status, 403);
  assert.match(forbidden.headers.get("www-authenticate") ?? "", /insufficient_scope.*notes:write/u);
  const limited = failureResponse(new AuthError("rate_limited"), options);
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("retry-after"), "60");
  assert.equal(limited.headers.get("www-authenticate"), null);
  assert.equal(failureResponse(new AuthError("unavailable"), options).status, 503);
  const metadata = protectedResourceMetadata({
    ...options,
    issuer: "https://auth.example/api/auth",
  });
  assert.equal(metadata.headers.get("cache-control"), "no-store");
  assert.deepEqual(await metadata.json(), {
    resource,
    authorization_servers: ["https://auth.example/api/auth"],
    scopes_supported: ["notes:read", "notes:write"],
    bearer_methods_supported: ["header"],
  });
});
