import { Clock, Duration, Effect, Fiber, Result, Schema } from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import type { JWK } from "jose";

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

/**
 * What a verified credential proves: an OAuth client's access token or an API key. A request's
 * caller, `CurrentPrincipal`, is this or, on a trusted local surface, the process itself, which
 * no verifier produces: `Caller` of the `/session` entry.
 */
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
  /** Where this verifier keeps what it reads and finds what was read before: see `Store`. */
  readonly store: Store;
  readonly requiredScopes?: readonly string[];
  /** `false` refuses API keys without reading the issuer's key list; only OAuth access tokens are accepted. */
  readonly apiKeys?: boolean | undefined;
}

export interface Verifier {
  readonly verifyToken: (
    token: string
  ) => Effect.Effect<Principal, AuthenticationError>;
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
    })
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

const KeyListClaims = KeyList.Claims.pipe(
  Schema.fieldsAssign({ exp: Schema.Finite })
);

/** One verified key list: the entries it holds and how long they may decide. */
export interface Keys {
  /** Epoch milliseconds, by this host's clock: when the list was read. */
  readonly readAt: number;
  /** Epoch milliseconds: the end of the issuer's outage window for this list. */
  readonly expiresAt: number;
  readonly entries: ReadonlyMap<string, string>;
}

/**
 * The last JWKS document read from an issuer: its keys, which signing keys are resolved
 * from, or the operation that failed. Either answers until its lifetime or cooldown ends.
 */
export type SettledJwks =
  | { readonly readAt: number; readonly keys: readonly JWK[] }
  | { readonly readAt: number; readonly failure: string };

/** The last key list read for one resource of an issuer, and the last one that verified. */
export interface SettledKeyList {
  /** Epoch milliseconds: when the last read ended, which holds off the next for the cooldown. */
  readonly readAt: number;
  /** The operation the last read failed at; `undefined` when it succeeded. */
  readonly failure: string | undefined;
  /** The last list that verified, which decides through an outage until it expires. */
  readonly held: Keys | undefined;
}

/**
 * What verifiers have read and decoded, for every verifier given it: JWKS documents by
 * issuer, key lists by issuer and resource. It holds values only, never an Effect, fiber,
 * Promise, Response or timer, so it may live as long as the process, at module scope on a
 * runtime whose I/O belongs to one request, such as Cloudflare Workers. Every read runs in
 * the verification that misses, and writes its result back; concurrent misses each read.
 */
export interface Store {
  readonly jwks: Map<string, SettledJwks>;
  readonly keyLists: Map<string, SettledKeyList>;
}

/** An empty store: `const store = Verifier.store()`, once, where the process starts. */
export const store = (): Store => ({ jwks: new Map(), keyLists: new Map() });

const unauthorized = (cause?: unknown) => new Unauthorized({ cause });

const listRejected = (cause: unknown) =>
  new ProviderUnavailable({ operation: "key-list.verify", cause });

/** How long a JWKS document answers verification before it is read again. */
const documentLifetime = Duration.minutes(1);

/**
 * How long a read holds off the next one: a failed read of either document, and any read
 * of the key list, so a key the held list does not name reaches the issuer at most this often.
 */
const cooldown = Duration.seconds(5);

/**
 * How long each fetch of a key list read may take: the list, and the JWKS it is verified with
 * when none is held. Under `Resource`'s five-second deadline, so an issuer that stops answering
 * fails the read, not the request, and a held list still decides.
 */
const listReadTimeout = Duration.seconds(3);

const deadline =
  (operation: string) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    Effect.timeoutOrElse(effect, {
      duration: listReadTimeout,
      orElse: () => Effect.fail(new ProviderUnavailable({ operation })),
    });

/**
 * A verifier over `options.store`; transport is selected by the application, not the SDK.
 * It holds nothing but its options, the store and the HTTP client, so acquiring one per
 * request costs nothing: every read it makes runs in the verification that needs it.
 * Verification runs to completion: a deadline is the request edge's policy, which
 * `Resource` applies, so an in-process caller can await a provider call it cannot cancel.
 * The one exception is a key list read, which runs its fetches together and gives up on each
 * after three seconds.
 */
export const make = Effect.fn("Verifier.make")(function* (options: Options) {
  const client = yield* HttpClient.HttpClient;
  const listed = JSON.stringify([options.issuer, options.resource]);

  const endpoints = yield* Effect.try({
    try: () => ({
      jwks: new URL(`${options.issuer}/jwks`).href,
      keyList: new URL("/api/keyList", options.issuer).href,
    }),
    catch: () => new ConfigurationError({ message: "Invalid issuer URL" }),
  });

  const document = Effect.fn("Verifier.jwks")(function* () {
    const response = yield* execute(
      client,
      HttpClientRequest.get(endpoints.jwks)
    );

    if (response.status !== 200) {
      return yield* new ProviderUnavailable({
        operation: "jwks.fetch",
        cause: { status: response.status },
      });
    }

    const jwks = yield* HttpClientResponse.schemaBodyJson(Jwks)(response).pipe(
      Effect.mapError(
        (cause) => new ProviderUnavailable({ operation: "jwks.decode", cause })
      )
    );

    return jwks.keys.map(({ key_ops, ...key }): JWK =>
      key_ops ? { ...key, key_ops: [...key_ops] } : key
    );
  }, Effect.scoped);

  /** The keys read within their lifetime, a failed read's failure within its cooldown, or a read now. */
  const keys = Effect.gen(function* () {
    const settled = options.store.jwks.get(options.issuer);
    const startedAt = yield* Clock.currentTimeMillis;

    if (settled !== undefined) {
      const answers = "keys" in settled ? documentLifetime : cooldown;

      if (startedAt - settled.readAt < Duration.toMillis(answers)) {
        return "keys" in settled
          ? settled.keys
          : yield* new ProviderUnavailable({ operation: settled.failure });
      }
    }

    const read = yield* Effect.result(document());
    const readAt = yield* Clock.currentTimeMillis;

    if (Result.isSuccess(read)) {
      options.store.jwks.set(options.issuer, { readAt, keys: read.success });

      return read.success;
    }

    // why: a failure never replaces an outcome that ended after it began.
    if (
      (options.store.jwks.get(options.issuer)?.readAt ?? -Infinity) >= startedAt
    ) {
      return yield* read.failure;
    }

    options.store.jwks.set(options.issuer, {
      readAt,
      failure: read.failure.operation,
    });

    return yield* read.failure;
  });

  const signingKey = Effect.fn("Verifier.signingKey")(function* (
    kid: string,
    held: typeof keys
  ) {
    const jwks = { keys: [...(yield* held)] };

    return yield* Effect.tryPromise({
      try: async () => await createLocalJWKSet(jwks)({ alg: "EdDSA", kid }),
      catch: unauthorized,
    });
  });

  /**
   * A document this issuer signed for this resource: EdDSA under a key it names, with the
   * expected `typ`, issuer and audience, and not expired. Which claims it must carry is
   * its schema's to say. `Unauthorized` means it is not to be trusted; what that amounts
   * to is the caller's to say. Its signing keys are `held`'s, the store's JWKS by default.
   */
  const verifySigned = Effect.fn("Verifier.signed")(function* (
    jws: string,
    typ: string,
    held: typeof keys = keys
  ) {
    const header = yield* Effect.try({
      try: () => decodeProtectedHeader(jws),
      catch: unauthorized,
    });

    // why: refused before any JWKS read, so an unauthenticated request causes no issuer traffic.
    if (header.alg !== "EdDSA" || header.kid === undefined) {
      return yield* unauthorized();
    }

    const key = yield* signingKey(header.kid, held);
    const now = yield* Clock.currentTimeMillis;

    const { payload } = yield* Effect.tryPromise({
      try: async () =>
        await jwtVerify(jws, key, {
          issuer: options.issuer,
          audience: options.resource,
          algorithms: ["EdDSA"],
          typ,
          currentDate: new Date(now),
        }),
      catch: unauthorized,
    });

    return payload;
  });

  const verifyJwt = Effect.fn("Verifier.jwt")(function* (token: string) {
    const payload = yield* verifySigned(token, "at+jwt");

    if (payload["cnf"] !== undefined) {
      return yield* unauthorized();
    }

    const claims = yield* Schema.decodeUnknownEffect(Claims)(payload).pipe(
      Effect.mapError(unauthorized)
    );

    return {
      subject: claims.sub,
      scopes: claims.scope.split(" ").filter(Boolean),
      actor: { kind: "client", clientId: claims.client_id },
      expiresAt: claims.exp * 1000,
    } satisfies Principal;
  });

  const listDocument = Effect.fn("Verifier.keyList")(function* () {
    const request = HttpClientRequest.post(endpoints.keyList).pipe(
      HttpClientRequest.bodyJsonUnsafe({ resource: options.resource })
    );

    const fetched = Effect.gen(function* () {
      const response = yield* execute(client, request);

      if (response.status !== 200) {
        return yield* new ProviderUnavailable({
          operation: "key-list.fetch",
          cause: { status: response.status },
        });
      }

      return yield* HttpClientResponse.schemaBodyJson(KeyListResponse)(
        response
      ).pipe(
        Effect.mapError(
          (cause) =>
            new ProviderUnavailable({ operation: "key-list.decode", cause })
        )
      );
    });

    // why: the JWKS read runs beside the list's, on its own deadline, so neither spends the other's.
    const signing = yield* Effect.forkScoped(
      keys.pipe(deadline("jwks.timeout"))
    );

    const { list } = yield* fetched.pipe(deadline("key-list.timeout"));

    const payload = yield* verifySigned(
      list,
      KeyList.type,
      Fiber.join(signing)
    ).pipe(
      Effect.catchTag("Unauthorized", (cause) =>
        Effect.fail(listRejected(cause))
      )
    );

    const claims = yield* Schema.decodeUnknownEffect(KeyListClaims)(
      payload
    ).pipe(Effect.mapError(listRejected));

    return {
      readAt: yield* Clock.currentTimeMillis,
      expiresAt: claims.exp * 1000,
      entries: new Map(claims.keys.map((entry) => [entry.id, entry.sealed])),
    } satisfies Keys;
  }, Effect.scoped);

  /**
   * Read the key list, unless a read ended within the cooldown: then that read's outcome
   * stands. A list that verified is always written back; a failure is not, over a read that
   * ended after it began. A failure is logged once until a read succeeds again.
   */
  const readList = Effect.gen(function* () {
    const settled = options.store.keyLists.get(listed);
    const startedAt = yield* Clock.currentTimeMillis;

    if (
      settled !== undefined &&
      startedAt - settled.readAt < Duration.toMillis(cooldown)
    ) {
      return settled.failure === undefined
        ? undefined
        : yield* new ProviderUnavailable({ operation: settled.failure });
    }

    const read = yield* Effect.result(listDocument());

    const readAt = yield* Clock.currentTimeMillis;
    const before = options.store.keyLists.get(listed);
    const failing = before?.failure !== undefined;

    if (Result.isSuccess(read)) {
      options.store.keyLists.set(listed, {
        readAt,
        failure: undefined,
        held: read.success,
      });

      if (failing) {
        yield* Effect.logInfo("clankerauth key list reads have recovered");
      }

      return;
    }

    if ((before?.readAt ?? -Infinity) >= startedAt) {
      return yield* read.failure;
    }

    const { operation } = read.failure;
    options.store.keyLists.set(listed, {
      readAt,
      failure: operation,
      held: before?.held,
    });

    if (!failing) {
      yield* Effect.logWarning(
        "clankerauth key list reads are failing; a held list decides until it expires",
        { operation }
      );
    }

    return yield* read.failure;
  });

  /** The list read now, or within the cooldown, or else the held one, while inside its window. */
  const latest = Effect.gen(function* () {
    const fetched = yield* Effect.result(readList);
    const list = options.store.keyLists.get(listed)?.held;

    if (
      list !== undefined &&
      list.expiresAt > (yield* Clock.currentTimeMillis)
    ) {
      return list;
    }

    return yield* Result.isFailure(fetched)
      ? fetched.failure
      : new ProviderUnavailable({ operation: "key-list.expired" });
  });

  const verifyKey = Effect.fn("Verifier.apiKey")(function* (key: string) {
    const open = (list: Keys) =>
      Effect.tryPromise({
        try: async () =>
          await KeyList.open(key, options.resource, list.entries),
        catch: unauthorized,
      });

    const now = yield* Clock.currentTimeMillis;
    const current = options.store.keyLists.get(listed)?.held;

    const list =
      current !== undefined &&
      now - current.readAt < Duration.toMillis(keyListRefresh) &&
      current.expiresAt > now
        ? current
        : yield* latest;

    const grant =
      (yield* open(list)) ??
      (yield* Effect.flatMap(latest, (next) =>
        next === list ? Effect.undefined : open(next)
      ));

    if (grant === undefined) {
      return yield* unauthorized();
    }

    if (
      grant.expiresAt !== null &&
      grant.expiresAt <= (yield* Clock.currentTimeMillis)
    ) {
      return yield* unauthorized();
    }

    return {
      subject: grant.ownerId,
      scopes: grant.scopes,
      actor: { kind: "key", keyId: grant.keyId },
      expiresAt: grant.expiresAt ?? undefined,
    } satisfies Principal;
  });

  const verifyToken = Effect.fn("Verifier.verifyToken")(function* (
    token: string
  ) {
    const isKey = token.startsWith(KeyList.keyPrefix);

    if (isKey && options.apiKeys === false) {
      return yield* unauthorized();
    }

    const principal = yield* isKey ? verifyKey(token) : verifyJwt(token);

    const missing = options.requiredScopes?.find(
      (scope) => !principal.scopes.includes(scope)
    );

    if (missing !== undefined) {
      return yield* new InsufficientScope({
        scope: missing,
        actor: principal.actor,
      });
    }

    return principal;
  });

  return { verifyToken } satisfies Verifier;
});
