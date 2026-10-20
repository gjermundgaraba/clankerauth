import assert from "node:assert/strict";
import type { JWTPayload } from "jose";
import { it } from "@effect/vitest";
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

type Issuer = Effect.Success<ReturnType<typeof startIssuer>>;

const verifierFor = (issuer: Issuer, target = resource, store = Verifier.store()) =>
  withHttp(
    Verifier.make({
      issuer: issuer.issuer,
      resource: target,
      store,
      requiredScopes: ["notes:read"],
    }),
  );

const withIssuer = Effect.gen(function* () {
  const issuer = yield* startIssuer(resource);
  const store = Verifier.store();

  return { verifier: yield* verifierFor(issuer, resource, store), issuer, store };
});

const sign = (issuer: Issuer, ...args: Parameters<Issuer["sign"]>) =>
  Effect.promise(() => issuer.sign(...args));

it.live("API keys verify offline against one key list, with their actor, scopes and expiry", () =>
  Effect.gen(function* () {
    const { verifier, issuer, store } = yield* withIssuer;
    const principal = yield* verifier.verifyToken(issuer.key);
    assert.equal(principal.subject, "owner");
    assert.deepEqual(principal.actor, { kind: "key", keyId: "key-1" });
    assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
    assert.equal(principal.expiresAt, undefined);
    assert.deepEqual((yield* verifier.verifyToken(issuer.readOnlyKey)).scopes, ["notes:read"]);
    assert.equal(issuer.keyLists(), 1);

    assert(
      (yield* Effect.flip(verifier.verifyToken(`clankerauth_${"x".repeat(43)}`))) instanceof
        Unauthorized,
    );

    issuer.revoke(issuer.key);
    yield* verifier.verifyToken(issuer.key);
    yield* (yield* verifierFor(issuer, resource, store)).verifyToken(issuer.key);
    assert.equal(issuer.keyLists(), 1);
    assert(
      (yield* Effect.flip((yield* verifierFor(issuer)).verifyToken(issuer.key))) instanceof
        Unauthorized,
    );

    const expiresAt = new Date(Date.now() + 60_000);
    const expiring = issuer.apiKey(undefined, expiresAt);
    const listed = yield* verifierFor(issuer);
    assert.equal((yield* listed.verifyToken(expiring)).expiresAt, expiresAt.getTime());

    const reports = "https://reports.internal/api";

    const both = issuer.apiKey({
      [resource]: ["notes:write", "notes:read"],
      [reports]: ["notes:read"],
    });

    const elsewhere = yield* verifierFor(issuer, reports);
    assert.deepEqual((yield* elsewhere.verifyToken(both)).scopes, ["notes:read"]);

    assert((yield* Effect.flip(elsewhere.verifyToken(issuer.readOnlyKey))) instanceof Unauthorized);
  }),
);

it.live("JWTs bind exact issuer, audience, claims, lifetime and required scopes", () =>
  Effect.gen(function* () {
    const { verifier, issuer } = yield* withIssuer;
    const token = yield* sign(issuer);
    const principal = yield* verifier.verifyToken(token);
    assert.deepEqual(principal.actor, { kind: "client", clientId: "fixture" });
    assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
    assert.equal(issuer.keyLists(), 0);

    const other = yield* withHttp(
      Verifier.make({
        issuer: issuer.issuer,
        resource: `${publicUrl}/mcp`,
        store: Verifier.store(),
      }),
    );

    assert((yield* Effect.flip(other.verifyToken(token))) instanceof Unauthorized);

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
        (yield* Effect.flip(verifier.verifyToken(yield* sign(issuer, claim)))) instanceof
          Unauthorized,
      );
    assert(
      (yield* Effect.flip(verifier.verifyToken(yield* sign(issuer, {}, "JWT")))) instanceof
        Unauthorized,
    );
    yield* verifier.verifyToken(
      yield* sign(issuer, { aud: [resource, "https://reports.internal/api"] }),
    );
    assert.deepEqual(
      yield* Effect.flip(verifier.verifyToken(yield* sign(issuer, { scope: "notes:write" }))),
      new InsufficientScope({
        scope: "notes:read",
        actor: { kind: "client", clientId: "fixture" },
      }),
    );
  }),
);

it.live("malformed credentials and outages remain distinct typed outcomes", () =>
  Effect.gen(function* () {
    const { verifier, issuer } = yield* withIssuer;

    for (const token of [
      "",
      "invalid,",
      "not.a.jwt",
      "eyJhbGciOiJIUzI1NiJ9.e30.AA",
      `${Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "at+jwt" })).toString("base64url")}.e30.AA`,
    ])
      assert((yield* Effect.flip(verifier.verifyToken(token))) instanceof Unauthorized);
    assert.equal(issuer.keyLists(), 0);
    issuer.fail(503);
    assert((yield* Effect.flip(verifier.verifyToken(issuer.key))) instanceof ProviderUnavailable);
    assert(
      (yield* Effect.flip(verifier.verifyToken(yield* sign(issuer)))) instanceof
        ProviderUnavailable,
    );
  }),
);

it.effect("invalid standalone verifier configuration fails at construction", () =>
  Effect.gen(function* () {
    const error = yield* Effect.flip(
      withHttp(Verifier.make({ issuer: "not a URL", resource, store: Verifier.store() })),
    );

    assert(error instanceof ConfigurationError);
  }),
);

it.live("the fake issuer rejects malformed key list requests", () =>
  Effect.gen(function* () {
    const issuer = yield* startIssuer(resource);

    for (const body of ["invalid", "{}", "[]", "null", '{"resource":42}']) {
      const response = yield* Effect.promise(() =>
        fetch(new URL("/api/keyList", issuer.issuer), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body,
        }),
      );

      assert.equal(response.status, 400);
      yield* Effect.promise(async () => response.body?.cancel());
    }
  }),
);
