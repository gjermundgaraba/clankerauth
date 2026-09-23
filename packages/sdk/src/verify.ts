import { Cause, Clock, DateTime, Effect, Exit, Schema } from "effect";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";
import {
  ConfigurationError,
  InsufficientScope,
  ProviderUnavailable,
  RateLimited,
  Unauthorized,
} from "./errors.ts";
import type { AuthenticationError } from "./errors.ts";
import { execute } from "./transport.ts";

export interface Principal {
  readonly subject: string;
  readonly scopes: readonly string[];
  readonly actor:
    | { readonly kind: "client"; readonly clientId: string }
    | { readonly kind: "key"; readonly keyId: string };
  /**
   * When this credential stops being valid, in epoch milliseconds: an access token's
   * verified `exp`, so a host never decodes the token again. `undefined` for an API
   * key, which has no token lifetime and is re-verified against the issuer on every
   * request; a host that caches a key decision must choose its own bound.
   */
  readonly expiresAt: number | undefined;
}

export interface Options {
  readonly issuer: string;
  readonly resource: string;
  readonly requiredScopes?: readonly string[];
  /** `false` rejects API keys without consulting the issuer; only OAuth access tokens are accepted. */
  readonly apiKeys?: boolean;
}

export interface Verifier {
  readonly verify: (
    authorization: string | null | undefined,
  ) => Effect.Effect<Principal, AuthenticationError>;
  readonly verifyToken: (token: string) => Effect.Effect<Principal, AuthenticationError>;
}

const Jwks = Schema.Struct({
  keys: Schema.Array(
    Schema.Struct({
      kty: Schema.String,
      crv: Schema.optionalKey(Schema.String),
      x: Schema.optionalKey(Schema.String),
      kid: Schema.optionalKey(Schema.String),
      alg: Schema.optionalKey(Schema.String),
      use: Schema.optionalKey(Schema.String),
      key_ops: Schema.optionalKey(Schema.Array(Schema.String)),
    }),
  ),
});

const Claims = Schema.Struct({
  sub: Schema.NonEmptyString,
  client_id: Schema.NonEmptyString,
  scope: Schema.String,
  exp: Schema.Finite,
});

const KeyResponse = Schema.Struct({
  keyId: Schema.NonEmptyString,
  ownerId: Schema.NonEmptyString,
  resource: Schema.String,
  scopes: Schema.Array(Schema.NonEmptyString),
  expiresAt: Schema.NullOr(Schema.DateTimeUtcFromString),
});

const unauthorized = () => new Unauthorized({ message: "Authentication required" });

/** How long a JWKS document answers verification before it is read again. */
const documentLifetime = "1 minute";

/** How long a failed read holds off the next one. */
const failureCooldown = "5 seconds";

/**
 * Acquire once per resource; transport is selected by the application, not the SDK.
 * Verification runs to completion: a deadline is the request edge's policy, which
 * `Resource` applies, so an in-process caller can await a provider call it cannot cancel.
 */
export const make = Effect.fn("Verifier.make")(function* (options: Options) {
  const client = yield* HttpClient.HttpClient;

  const endpoints = yield* Effect.try({
    try: () => ({
      jwks: new URL(`${options.issuer}/jwks`).href,
      apiKey: new URL("/api/issuer/verifyApiKey", options.issuer).href,
    }),
    catch: () => new ConfigurationError({ message: "Invalid issuer URL" }),
  });

  const document = Effect.fn("Verifier.jwks")(function* () {
    const response = yield* execute(client, HttpClientRequest.get(endpoints.jwks));

    if (response.status !== 200)
      return yield* new ProviderUnavailable({
        operation: "jwks.fetch",
        cause: { status: response.status },
      });

    const jwks = yield* HttpClientResponse.schemaBodyJson(Jwks)(response).pipe(
      Effect.mapError((cause) => new ProviderUnavailable({ operation: "jwks.decode", cause })),
    );

    return createLocalJWKSet({
      keys: jwks.keys.map(({ key_ops, ...key }) =>
        key_ops ? { ...key, key_ops: [...key_ops] } : key,
      ),
    });
  }, Effect.scoped);

  // One read serves every key identifier until it expires, whatever its outcome, so an
  // unknown `kid` in an unauthenticated request never becomes traffic at the issuer.
  const read = yield* Effect.cachedWithTTL(document(), (exit) =>
    Exit.isSuccess(exit) ? documentLifetime : failureCooldown,
  );

  // Replaying that read must not hand a later request the interruption of an earlier
  // one's deadline; within the window the issuer simply was not reached.
  const keys = Effect.catchCause(read, (cause) =>
    Cause.hasInterrupts(cause)
      ? Effect.fail(new ProviderUnavailable({ operation: "jwks.refresh" }))
      : Effect.failCause(cause),
  );

  const signingKey = Effect.fn("Verifier.signingKey")(function* (kid: string) {
    const resolve = yield* keys;

    return yield* Effect.tryPromise({
      try: () => resolve({ alg: "EdDSA", kid }),
      // Selecting from fetched keys does no I/O: every failure is the credential's.
      catch: unauthorized,
    });
  });

  const verifyJwt = Effect.fn("Verifier.jwt")(function* (token: string) {
    const header = yield* Effect.try({
      try: () => decodeProtectedHeader(token),
      catch: unauthorized,
    });

    // The issuer always names its key, so key selection is never ambiguous. Reject other
    // tokens before doing provider I/O; JOSE still enforces its algorithm allowlist.
    if (header.alg !== "EdDSA" || header.kid === undefined) return yield* unauthorized();
    const key = yield* signingKey(header.kid);
    const now = yield* Clock.currentTimeMillis;

    const { payload } = yield* Effect.tryPromise({
      try: () =>
        jwtVerify(token, key, {
          issuer: options.issuer,
          audience: options.resource,
          algorithms: ["EdDSA"],
          typ: "at+jwt",
          requiredClaims: ["sub", "client_id", "scope", "iat", "exp"],
          currentDate: new Date(now),
        }),
      // Verification against a resolved key does no I/O either.
      catch: unauthorized,
    });

    if (payload.cnf !== undefined) return yield* unauthorized();

    const claims = yield* Schema.decodeUnknownEffect(Claims)(payload).pipe(
      Effect.mapError(unauthorized),
    );

    return {
      subject: claims.sub,
      scopes: claims.scope.split(" ").filter(Boolean),
      actor: { kind: "client", clientId: claims.client_id },
      // `jwtVerify` already checked this claim against the current time.
      expiresAt: claims.exp * 1000,
    } satisfies Principal;
  });

  const verifyKey = Effect.fn("Verifier.apiKey")(function* (key: string) {
    const request = HttpClientRequest.post(endpoints.apiKey).pipe(
      HttpClientRequest.setHeader("authorization", `Bearer ${key}`),
      HttpClientRequest.bodyJsonUnsafe({ resource: options.resource }),
    );

    const response = yield* execute(client, request);

    // The issuer answers 403 for a key with no grant on this resource. That is the same
    // case as a token for another audience: the credential is not this resource's.
    if (response.status === 401 || response.status === 403) return yield* unauthorized();

    if (response.status === 429)
      return yield* new RateLimited({ message: "Authentication rate exceeded" });

    if (response.status !== 200)
      return yield* new ProviderUnavailable({
        operation: "api-key.verify",
        cause: { status: response.status },
      });

    const body = yield* HttpClientResponse.schemaBodyJson(KeyResponse)(response).pipe(
      Effect.mapError((cause) => new ProviderUnavailable({ operation: "api-key.response", cause })),
    );

    if (body.resource !== options.resource)
      return yield* new ProviderUnavailable({ operation: "api-key.response" });

    if (
      body.expiresAt !== null &&
      DateTime.toEpochMillis(body.expiresAt) <= (yield* Clock.currentTimeMillis)
    )
      return yield* unauthorized();

    return {
      subject: body.ownerId,
      scopes: body.scopes,
      actor: { kind: "key", keyId: body.keyId },
      // A key's own expiry is enforced above, on every verification; it is not a
      // lifetime a caller may hold a decision for.
      expiresAt: undefined,
    } satisfies Principal;
  }, Effect.scoped);

  const verifyToken = Effect.fn("Verifier.verifyToken")(function* (token: string) {
    const principal = yield* token.startsWith("clankerauth_")
      ? options.apiKeys === false
        ? Effect.fail(unauthorized())
        : verifyKey(token)
      : verifyJwt(token);

    const missing = options.requiredScopes?.find((scope) => !principal.scopes.includes(scope));

    if (missing !== undefined) return yield* new InsufficientScope({ scope: missing });

    return principal;
  });

  return {
    verifyToken,
    verify: Effect.fn("Verifier.verify")(function* (authorization: string | null | undefined) {
      const token = /^Bearer ([^\s,]+)$/iu.exec(authorization ?? "")?.[1];

      if (!token) return yield* unauthorized();

      return yield* verifyToken(token);
    }),
  } satisfies Verifier;
});
