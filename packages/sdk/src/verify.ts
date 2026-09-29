import { Cause, Clock, Effect, Exit, Ref, Result, Schema } from "effect";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";
import {
  ConfigurationError,
  InsufficientScope,
  ProviderUnavailable,
  Unauthorized,
} from "./errors.ts";
import type { AuthenticationError } from "./errors.ts";
import * as KeyList from "./key-list.ts";
import { keyListRefresh } from "./refresh.ts";
import { execute } from "./transport.ts";

export interface Principal {
  readonly subject: string;
  readonly scopes: readonly string[];
  readonly actor:
    | { readonly kind: "client"; readonly clientId: string }
    | { readonly kind: "key"; readonly keyId: string };
  /**
   * When this credential stops being valid, in epoch milliseconds: an access token's
   * verified `exp`, so a host never decodes the token again, or an API key's expiry.
   * `undefined` for a key that does not expire. A key can also be revoked before then;
   * `Resource.watch` ends a connection at whichever comes first.
   */
  readonly expiresAt: number | undefined;
}

export interface Options {
  readonly issuer: string;
  readonly resource: string;
  readonly requiredScopes?: readonly string[];
  /** `false` refuses API keys without reading the issuer's key list; only OAuth access tokens are accepted. */
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
  iat: Schema.Finite,
  exp: Schema.Finite,
});

/** The list document as the issuer's `keyList` action answers it. */
const KeyListResponse = Schema.Struct({ list: Schema.String });

const KeyListClaims = KeyList.Claims.pipe(Schema.fieldsAssign({ exp: Schema.Finite }));

/** One verified key list: the entries it holds and how long they may decide. */
interface Keys {
  /** Epoch milliseconds: the end of the issuer's outage window for this list. */
  readonly expiresAt: number;
  readonly entries: ReadonlyMap<string, string>;
}

const unauthorized = (cause?: unknown) =>
  new Unauthorized({ message: "Authentication required", cause });

/** How long a JWKS document answers verification before it is read again. */
const documentLifetime = "1 minute";

/** How long a failed read holds off the next one. */
const failureCooldown = "5 seconds";

/**
 * How long a key list read may take. Under `Resource`'s five-second deadline, so a stalled
 * issuer fails the read, not the request, and a held list still decides.
 */
const listReadTimeout = "3 seconds";

/**
 * Acquire once per resource; transport is selected by the application, not the SDK.
 * Verification runs to completion: a deadline is the request edge's policy, which
 * `Resource` applies, so an in-process caller can await a provider call it cannot cancel.
 * The one exception is a key list read, which gives up after three seconds.
 */
export const make = Effect.fn("Verifier.make")(function* (options: Options) {
  const client = yield* HttpClient.HttpClient;

  const endpoints = yield* Effect.try({
    try: () => ({
      jwks: new URL(`${options.issuer}/jwks`).href,
      keyList: new URL("/api/issuer/keyList", options.issuer).href,
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

  // Replaying a read must not hand a later request the interruption of an earlier
  // one's deadline; within the window the issuer simply was not reached.
  const replayed = <A>(cached: Effect.Effect<A, ProviderUnavailable>, operation: string) =>
    Effect.catchCause(cached, (cause) =>
      Cause.hasInterrupts(cause)
        ? Effect.fail(new ProviderUnavailable({ operation }))
        : Effect.failCause(cause),
    );

  const keys = replayed(read, "jwks.refresh");

  const signingKey = Effect.fn("Verifier.signingKey")(function* (kid: string) {
    const resolve = yield* keys;

    return yield* Effect.tryPromise({
      try: () => resolve({ alg: "EdDSA", kid }),
      // Selecting from fetched keys does no I/O: every failure is the credential's.
      catch: unauthorized,
    });
  });

  /**
   * A document this issuer signed for this resource: EdDSA under a key it names, with the
   * expected `typ`, issuer and audience, and not expired. Which claims it must carry is
   * its schema's to say. `Unauthorized` means it is not to be trusted; what that amounts
   * to is the caller's to say.
   */
  const verifySigned = Effect.fn("Verifier.signed")(function* (jws: string, typ: string) {
    const header = yield* Effect.try({
      try: () => decodeProtectedHeader(jws),
      catch: unauthorized,
    });

    // The issuer always names its key, so key selection is never ambiguous. Reject other
    // documents before doing provider I/O; JOSE still enforces its algorithm allowlist.
    if (header.alg !== "EdDSA" || header.kid === undefined) return yield* unauthorized();
    const key = yield* signingKey(header.kid);
    const now = yield* Clock.currentTimeMillis;

    const { payload } = yield* Effect.tryPromise({
      try: () =>
        jwtVerify(jws, key, {
          issuer: options.issuer,
          audience: options.resource,
          algorithms: ["EdDSA"],
          typ,
          currentDate: new Date(now),
        }),
      // Verification against a resolved key does no I/O either.
      catch: unauthorized,
    });

    return payload;
  });

  const verifyJwt = Effect.fn("Verifier.jwt")(function* (token: string) {
    const payload = yield* verifySigned(token, "at+jwt");

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

  const listDocument = Effect.fn("Verifier.keyList")(function* () {
    const request = HttpClientRequest.post(endpoints.keyList).pipe(
      HttpClientRequest.bodyJsonUnsafe({ resource: options.resource }),
    );

    const response = yield* execute(client, request);

    if (response.status !== 200)
      return yield* new ProviderUnavailable({
        operation: "key-list.fetch",
        cause: { status: response.status },
      });

    const { list } = yield* HttpClientResponse.schemaBodyJson(KeyListResponse)(response).pipe(
      Effect.mapError((cause) => new ProviderUnavailable({ operation: "key-list.decode", cause })),
    );

    // A list that does not verify is no list: the held one keeps deciding.
    const rejected = (cause: unknown) =>
      new ProviderUnavailable({ operation: "key-list.verify", cause });

    const payload = yield* verifySigned(list, KeyList.type).pipe(
      Effect.catchTag("Unauthorized", (cause) => Effect.fail(rejected(cause))),
    );

    const claims = yield* Schema.decodeUnknownEffect(KeyListClaims)(payload).pipe(
      Effect.mapError(rejected),
    );

    return {
      expiresAt: claims.exp * 1000,
      entries: new Map(claims.keys.map((entry) => [entry.id, entry.sealed])),
    } satisfies Keys;
  }, Effect.scoped);

  // While a list is held, a failing issuer is otherwise invisible until that list runs
  // out. Reads are logged when they start failing and when they recover, not per retry.
  const failing = yield* Ref.make(false);

  const readList = yield* Effect.cachedWithTTL(
    listDocument().pipe(
      Effect.timeoutOrElse({
        duration: listReadTimeout,
        orElse: () => Effect.fail(new ProviderUnavailable({ operation: "key-list.timeout" })),
      }),
      Effect.tapError(({ operation }) =>
        Effect.flatMap(Ref.getAndSet(failing, true), (was) =>
          was
            ? Effect.void
            : Effect.logWarning(
                "clankerauth key list reads are failing; a held list decides until it expires",
                { operation },
              ),
        ),
      ),
      Effect.tap(() =>
        Effect.flatMap(Ref.getAndSet(failing, false), (was) =>
          was ? Effect.logInfo("clankerauth key list reads have recovered") : Effect.void,
        ),
      ),
    ),
    (exit) => (Exit.isSuccess(exit) ? keyListRefresh : failureCooldown),
  );

  // The list is verified once, when it is read. Holding its entries, not the document,
  // is what lets keys verify through an outage that has already taken JWKS with it.
  const held = yield* Ref.make<Keys | undefined>(undefined);

  /** The last verified list, while it is inside its window. */
  const keyList = Effect.gen(function* () {
    const fetched = yield* Effect.result(replayed(readList, "key-list.refresh"));

    if (Result.isSuccess(fetched)) yield* Ref.set(held, fetched.success);
    const list = yield* Ref.get(held);

    // A read is cached past its own check, so the window is checked on every use.
    if (list !== undefined && list.expiresAt > (yield* Clock.currentTimeMillis)) return list;

    return yield* Result.isFailure(fetched)
      ? fetched.failure
      : new ProviderUnavailable({ operation: "key-list.expired" });
  });

  const verifyKey = Effect.fn("Verifier.apiKey")(function* (key: string) {
    const list = yield* keyList;

    const grant = yield* Effect.tryPromise({
      try: () => KeyList.open(key, options.resource, list.entries),
      catch: unauthorized,
    });

    // No entry is the same case as a token for another audience: not this resource's.
    if (grant === undefined) return yield* unauthorized();

    if (grant.expiresAt !== null && grant.expiresAt <= (yield* Clock.currentTimeMillis))
      return yield* unauthorized();

    return {
      subject: grant.ownerId,
      scopes: grant.scopes,
      actor: { kind: "key", keyId: grant.keyId },
      expiresAt: grant.expiresAt ?? undefined,
    } satisfies Principal;
  });

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
