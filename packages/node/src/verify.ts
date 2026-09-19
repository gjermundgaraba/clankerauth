import { Clock, Effect, Exit, Schema, Semaphore } from "effect";
import { createLocalJWKSet, decodeProtectedHeader, errors, jwtVerify } from "jose";
import type { JWSHeaderParameters } from "jose";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";
import {
  ConfigurationError,
  Forbidden,
  ProviderUnavailable,
  RateLimited,
  Unauthorized,
} from "./errors.ts";
import { execute } from "./transport.ts";

export interface Principal {
  readonly subject: string;
  readonly scopes: readonly string[];
  readonly actor:
    | { readonly kind: "client"; readonly clientId: string }
    | { readonly kind: "key"; readonly keyId: string };
}

export interface Options {
  readonly issuer: string;
  readonly resource: string;
  readonly requiredScopes?: readonly string[];
}

export interface Verifier {
  readonly verify: (
    authorization: string | null | undefined,
  ) => Effect.Effect<Principal, VerificationError>;
  readonly verifyToken: (token: string) => Effect.Effect<Principal, VerificationError>;
}

export type VerificationError = Unauthorized | Forbidden | RateLimited | ProviderUnavailable;

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
});

const KeyResponse = Schema.Struct({
  keyId: Schema.NonEmptyString,
  ownerId: Schema.NonEmptyString,
  resource: Schema.String,
  scopes: Schema.Array(Schema.NonEmptyString),
  expiresAt: Schema.NullOr(Schema.String),
});

const credentialErrors = [
  errors.JWTExpired,
  errors.JWTClaimValidationFailed,
  errors.JWSSignatureVerificationFailed,
  errors.JWSInvalid,
  errors.JWTInvalid,
  errors.JOSENotSupported,
  errors.JOSEAlgNotAllowed,
  errors.JWKSNoMatchingKey,
];

const unauthorized = () => new Unauthorized({ message: "Authentication required" });

/** Acquire once per resource; transport is selected by the application, not the SDK. */
export const make = Effect.fn("Verifier.make")(function* (options: Options) {
  const client = yield* HttpClient.HttpClient;

  const endpoints = yield* Effect.try({
    try: () => ({
      jwks: new URL(`${options.issuer}/jwks`).href,
      apiKey: new URL("/api/issuer/verifyApiKey", options.issuer).href,
    }),
    catch: () => new ConfigurationError({ message: "Invalid issuer URL" }),
  });

  const refreshLock = yield* Semaphore.make(1);
  let refreshAfter = 0;
  let refreshFailure: ProviderUnavailable | undefined;

  const makeCachedKeys = Effect.cachedWithTTL(
    Effect.gen(function* () {
      const response = yield* execute(client, HttpClientRequest.get(endpoints.jwks));

      if (response.status !== 200)
        return yield* new ProviderUnavailable({
          operation: "jwks.fetch",
          cause: { status: response.status },
        });

      const document = yield* HttpClientResponse.schemaBodyJson(Jwks)(response).pipe(
        Effect.mapError((cause) => new ProviderUnavailable({ operation: "jwks.decode", cause })),
      );

      refreshAfter = (yield* Clock.currentTimeMillis) + 30_000;
      refreshFailure = undefined;

      return createLocalJWKSet({
        keys: document.keys.map(({ key_ops, ...key }) =>
          key_ops ? { ...key, key_ops: [...key_ops] } : key,
        ),
      });
    }).pipe(Effect.scoped),
    (exit) => (Exit.isSuccess(exit) ? "10 minutes" : 0),
  );

  let keys = yield* makeCachedKeys;

  const resolveKey = (resolve: ReturnType<typeof createLocalJWKSet>, header: JWSHeaderParameters) =>
    Effect.tryPromise({
      try: () => resolve(header),
      catch: (cause) =>
        cause instanceof errors.JWKSNoMatchingKey
          ? unauthorized()
          : new ProviderUnavailable({ operation: "jwks.resolve", cause }),
    });

  const signingKey = Effect.fn("Verifier.signingKey")(function* (header: JWSHeaderParameters) {
    const resolve = yield* keys;

    return yield* resolveKey(resolve, header).pipe(
      Effect.catchTag("Unauthorized", () =>
        refreshLock.withPermit(
          Effect.gen(function* () {
            const current = yield* keys;

            // Another request may have refreshed while this one waited for admission.
            if (current !== resolve) return yield* resolveKey(current, header);
            const now = yield* Clock.currentTimeMillis;

            // Cool down failed or interrupted refreshes too, without discarding still-valid cached keys.
            if (now < refreshAfter) return yield* refreshFailure ?? unauthorized();
            refreshAfter = now + 30_000;
            refreshFailure = new ProviderUnavailable({ operation: "jwks.refresh" });
            const next = yield* makeCachedKeys;

            const refreshed = yield* next.pipe(
              Effect.tapError((error) =>
                Effect.sync(() => {
                  refreshFailure = error;
                }),
              ),
            );

            keys = next;

            return yield* resolveKey(refreshed, header);
          }),
        ),
      ),
    );
  });

  const verifyJwt = Effect.fn("Verifier.jwt")(function* (token: string) {
    const header = yield* Effect.try({
      try: () => decodeProtectedHeader(token),
      catch: unauthorized,
    });

    // Reject unsupported algorithms before doing provider I/O; JOSE still enforces its allowlist.
    if (header.alg !== "EdDSA") return yield* unauthorized();
    const key = yield* signingKey(header);
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
      catch: (cause) =>
        credentialErrors.some((kind) => cause instanceof kind)
          ? unauthorized()
          : new ProviderUnavailable({ operation: "jwt.verify", cause }),
    });

    if (payload.cnf !== undefined) return yield* unauthorized();

    const claims = yield* Schema.decodeUnknownEffect(Claims)(payload).pipe(
      Effect.mapError(unauthorized),
    );

    return {
      subject: claims.sub,
      scopes: claims.scope.split(" ").filter(Boolean),
      actor: { kind: "client", clientId: claims.client_id },
    } satisfies Principal;
  });

  const verifyKey = Effect.fn("Verifier.apiKey")(function* (key: string) {
    const request = HttpClientRequest.post(endpoints.apiKey).pipe(
      HttpClientRequest.setHeader("authorization", `Bearer ${key}`),
      HttpClientRequest.bodyJsonUnsafe({ resource: options.resource }),
    );

    const response = yield* execute(client, request);

    if (response.status === 401) return yield* unauthorized();

    if (response.status === 403) return yield* new Forbidden({ message: "Insufficient scope" });

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

    const expiry = body.expiresAt === null ? null : Date.parse(body.expiresAt);

    if (body.resource !== options.resource || (expiry !== null && !Number.isFinite(expiry)))
      return yield* new ProviderUnavailable({ operation: "api-key.response" });

    if (expiry !== null && expiry <= (yield* Clock.currentTimeMillis)) return yield* unauthorized();

    return {
      subject: body.ownerId,
      scopes: body.scopes,
      actor: { kind: "key", keyId: body.keyId },
    } satisfies Principal;
  }, Effect.scoped);

  const verifyToken = Effect.fn("Verifier.verifyToken")(
    function* (token: string) {
      const principal = yield* token.startsWith("ca_") ? verifyKey(token) : verifyJwt(token);

      if (options.requiredScopes?.some((scope) => !principal.scopes.includes(scope)))
        return yield* new Forbidden({ message: "Insufficient scope" });

      return principal;
    },
    Effect.timeoutOrElse({
      duration: "5 seconds",
      orElse: () => Effect.fail(new ProviderUnavailable({ operation: "verify.timeout" })),
    }),
  );

  return {
    verifyToken,
    verify: Effect.fn("Verifier.verify")(function* (authorization: string | null | undefined) {
      const token = /^Bearer ([^\s,]+)$/iu.exec(authorization ?? "")?.[1];

      if (!token) return yield* unauthorized();

      return yield* verifyToken(token);
    }),
  } satisfies Verifier;
});
