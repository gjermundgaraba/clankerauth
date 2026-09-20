import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { Clock, Effect, Exit, Redacted, Result, Schema } from "effect";
import * as oauth from "oauth4webapi";
import { Cookies, HttpClient } from "effect/unstable/http";
import {
  ConfigurationError,
  Forbidden,
  InvalidRequest,
  ProviderUnavailable,
  Unauthorized,
} from "./errors.ts";
import { SessionStore } from "./store.ts";
import type { Verifier } from "./verify.ts";
import { protocolTransport, TransportFailure } from "./transport.ts";
import * as Coordination from "./coordination.ts";

export interface Options {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
  readonly callbackUrl: string;
  readonly resource: string;
  readonly scopes: readonly string[];
  readonly secret: Redacted.Redacted<string>;
  readonly cookie: { readonly name: string; readonly lifetime?: number };
  readonly verifyToken: Verifier["verifyToken"];
}

const Credentials = Schema.Struct({
  accessToken: Schema.String,
  refreshToken: Schema.optionalKey(Schema.String),
  accessExpires: Schema.Finite,
  subject: Schema.String,
  refreshBlocked: Schema.Boolean,
});

type Credentials = typeof Credentials.Type;

const Login = Schema.Struct({
  verifier: Schema.String,
  state: Schema.String,
  nonce: Schema.String,
  returnTo: Schema.String,
});

type Login = typeof Login.Type;

export const transactionLifetime = 600;

const hash = (value: string) => createHash("sha256").update(value).digest("hex");

const random = () => randomBytes(32).toString("base64url");

const unauthorized = (cause?: unknown) => new Unauthorized({ message: "Sign in required", cause });

const pkceChallenge = Effect.fn("BrowserSession.pkceChallenge")((verifier: string) =>
  Effect.promise(() => oauth.calculatePKCECodeChallenge(verifier)),
);

/** Domain/session capability. Cookies and HTTP response mapping live in BrowserActions. */
export const make = Effect.fn("BrowserSession.make")(function* (options: Options) {
  const store = yield* SessionStore;
  const locked = yield* Coordination.make;

  const parsed = yield* Effect.try({
    try: () => {
      const callback = new URL(options.callbackUrl);

      if (
        !["http:", "https:"].includes(callback.protocol) ||
        callback.username ||
        callback.password ||
        options.callbackUrl.includes("#")
      )
        throw new Error("Callback must be an HTTP(S) URL without credentials or fragment");

      return { callback, issuer: new URL(options.issuer) };
    },
    catch: () => new ConfigurationError({ message: "Invalid browser callback URL or issuer" }),
  });

  if (Redacted.value(options.secret).length < 32)
    return yield* new ConfigurationError({ message: "Browser session secret needs 32 characters" });

  if (
    ["session", "login"].some((suffix) =>
      Result.isFailure(Cookies.makeCookie(`${options.cookie.name}_${suffix}`, "")),
    )
  )
    return yield* new ConfigurationError({ message: "Invalid cookie name" });
  const { callback: callbackUrl, issuer } = parsed;
  const origin = callbackUrl.origin;
  const lifetime = options.cookie.lifetime ?? 30 * 24 * 60 * 60;

  if (!Number.isSafeInteger(lifetime) || lifetime <= 0)
    return yield* new ConfigurationError({ message: "Invalid cookie lifetime" });
  const redirectUri = options.callbackUrl;
  const key = createHash("sha256").update(Redacted.value(options.secret)).digest();
  const client: oauth.Client = { client_id: options.clientId };
  const clientAuth = oauth.ClientSecretBasic(Redacted.value(options.clientSecret));

  const seal = (value: Credentials | Login) => {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const bytes = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);

    return Buffer.concat([iv, cipher.getAuthTag(), bytes]).toString("base64url");
  };

  const open = Effect.fn("BrowserSession.open")(function* (payload: string) {
    return yield* Effect.try({
      try: () => {
        const bytes = Buffer.from(payload, "base64url");
        const cipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
        cipher.setAuthTag(bytes.subarray(12, 28));

        return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString("utf8");
      },
      catch: unauthorized,
    });
  });

  const decodeCredentials = (payload: string) =>
    open(payload).pipe(
      Effect.flatMap(Schema.decodeUnknownEffect(Schema.fromJsonString(Credentials))),
      Effect.mapError(unauthorized),
    );

  const decodeLogin = (payload: string) =>
    open(payload).pipe(
      Effect.flatMap(Schema.decodeUnknownEffect(Schema.fromJsonString(Login))),
      Effect.mapError(unauthorized),
    );

  const read = Effect.fn("BrowserSession.read")(function* (id: string) {
    const row = yield* store.get(id);

    if (!row) return yield* unauthorized();

    if (row.expires <= (yield* Clock.currentTimeMillis)) {
      yield* store.delete(id);

      return yield* unauthorized();
    }

    return row;
  });

  const write = (id: string, value: Credentials | Login, expires: number) =>
    Effect.suspend(() => store.put(id, seal(value), expires));

  // Library calls are the only Promise boundary. Transport and cancellation remain Effect-owned.
  const transportClient = yield* HttpClient.HttpClient;

  const protocol = <A>(
    operation: string,
    call: (
      requestOptions: oauth.HttpRequestOptions<"GET" | "POST", URLSearchParams | undefined>,
    ) => Promise<A>,
  ) =>
    Effect.gen(function* () {
      const fetch = yield* protocolTransport().pipe(
        Effect.provideService(HttpClient.HttpClient, transportClient),
      );

      return yield* Effect.tryPromise({
        try: (signal) =>
          call({
            signal,
            [oauth.customFetch]: fetch,
            [oauth.allowInsecureRequests]:
              issuer.protocol === "http:" &&
              ["localhost", "127.0.0.1", "[::1]"].includes(issuer.hostname),
          }),
        catch: (cause) => {
          if (cause instanceof TransportFailure) return cause;

          if (
            cause instanceof oauth.AuthorizationResponseError ||
            (cause instanceof oauth.OperationProcessingError &&
              (cause.code === oauth.JWT_TIMESTAMP_CHECK ||
                cause.code === oauth.JWT_CLAIM_COMPARISON)) ||
            (cause instanceof oauth.ResponseBodyError && cause.error === "invalid_grant")
          )
            return unauthorized(cause);

          return new ProviderUnavailable({ operation, cause });
        },
      }).pipe(
        Effect.catch((error) =>
          error instanceof TransportFailure
            ? Effect.failCause(error.effectCause).pipe(
                Effect.mapError((cause) =>
                  cause instanceof ProviderUnavailable
                    ? cause
                    : new ProviderUnavailable({ operation, cause }),
                ),
              )
            : Effect.fail(error),
        ),
      );
    }).pipe(
      Effect.timeoutOrElse({
        duration: "5 seconds",
        orElse: () => Effect.fail(new ProviderUnavailable({ operation })),
      }),
    );

  const provider = yield* Effect.cachedWithTTL(
    protocol("browser.discovery", async (opts) => {
      const metadata = await oauth.processDiscoveryResponse(
        issuer,
        await oauth.discoveryRequest(issuer, opts),
      );

      if (!metadata.authorization_endpoint) throw new Error("Missing authorization endpoint");
      const endpoint = new URL(metadata.authorization_endpoint);

      if (
        endpoint.protocol !== "https:" &&
        !(
          endpoint.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname)
        )
      )
        throw new Error("Authorization endpoint must use HTTPS or loopback HTTP");

      return { ...metadata, authorization_endpoint: endpoint.href };
    }),
    (exit) => (Exit.isSuccess(exit) ? Infinity : 0),
  );

  const credentials = Effect.fn("BrowserSession.credentials")(function* (
    result: oauth.TokenEndpointResponse,
    old?: Credentials,
  ) {
    if (result.token_type !== "bearer" || !result.expires_in) return yield* unauthorized();
    const verified = yield* options.verifyToken(result.access_token);

    if (old && old.subject !== verified.subject) return yield* unauthorized();
    const refreshToken = result.refresh_token ?? old?.refreshToken;

    const next: Credentials = {
      accessToken: result.access_token,
      accessExpires: (yield* Clock.currentTimeMillis) + result.expires_in * 1000,
      subject: verified.subject,
      refreshBlocked: false,
    };

    return refreshToken ? { ...next, refreshToken } : next;
  });

  const accessToken = Effect.fn("BrowserSession.accessToken")(function* (raw: string | undefined) {
    if (!raw) return yield* unauthorized();
    const id = `session:${hash(raw)}`;

    return yield* locked(
      id,
      Effect.gen(function* () {
        const row = yield* read(id);
        const saved = yield* decodeCredentials(row.payload);

        // A persisted in-flight refresh always requires reauthentication, even if its access token is fresh.
        if (saved.refreshBlocked) {
          yield* store.delete(id);

          return yield* unauthorized();
        }

        if (saved.accessExpires > (yield* Clock.currentTimeMillis) + 30_000)
          return saved.accessToken;

        if (!saved.refreshToken) {
          yield* store.delete(id);

          return yield* unauthorized();
        }

        const refreshToken = saved.refreshToken;
        const as = yield* provider;
        // Commit before the network call. Interruption/restart leaves a durable no-replay marker.
        yield* write(id, { ...saved, refreshBlocked: true }, row.expires).pipe(
          Effect.uninterruptible,
        );

        const refresh = Effect.gen(function* () {
          const result = yield* protocol("browser.refresh", async (opts) => {
            const response = await oauth.refreshTokenGrantRequest(
              as,
              client,
              clientAuth,
              refreshToken,
              {
                ...opts,
                additionalParameters: { resource: options.resource },
              },
            );

            const result = await oauth.processRefreshTokenResponse(as, client, response);

            if (result.id_token) await oauth.validateApplicationLevelSignature(as, response, opts);

            return result;
          });

          const next = yield* credentials(result, saved);
          const identity = oauth.getValidatedIdTokenClaims(result);

          if (identity && identity.sub !== next.subject) return yield* unauthorized();
          yield* write(id, next, row.expires).pipe(Effect.uninterruptible);

          return next.accessToken;
        });

        // Typed failures invalidate locally. Interruption leaves the marker; defects are not auth failures.
        return yield* refresh.pipe(Effect.tapError(() => store.delete(id)));
      }),
    );
  });

  const login = Effect.fn("BrowserSession.login")(function* (returnTo: string) {
    const target = yield* Effect.try({
      try: () => new URL(returnTo, origin),
      catch: () => new InvalidRequest({ message: "Invalid return destination" }),
    });

    if (
      !returnTo.startsWith("/") ||
      target.origin !== origin ||
      target.pathname === callbackUrl.pathname
    )
      return yield* new InvalidRequest({ message: "Invalid return destination" });
    const as = yield* provider;

    const raw = random();

    const transaction: Login = {
      verifier: oauth.generateRandomCodeVerifier(),
      state: oauth.generateRandomState(),
      nonce: oauth.generateRandomNonce(),
      returnTo: target.pathname + target.search + target.hash,
    };

    const challenge = yield* pkceChallenge(transaction.verifier);

    const authorization = new URL(as.authorization_endpoint);
    authorization.search = new URLSearchParams({
      client_id: options.clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: ["openid", "offline_access", ...options.scopes].join(" "),
      resource: options.resource,
      state: transaction.state,
      nonce: transaction.nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();
    const now = yield* Clock.currentTimeMillis;
    yield* store.sweep(now);
    yield* write(`login:${hash(raw)}`, transaction, now + transactionLifetime * 1000);

    return { url: authorization.href, transaction: raw };
  });

  const callback = Effect.fn("BrowserSession.callback")(function* (
    url: URL,
    raw: string | undefined,
  ) {
    if (
      url.searchParams.getAll("iss").length !== 1 ||
      url.searchParams.get("iss") !== options.issuer ||
      !raw
    )
      return yield* unauthorized();
    const id = `login:${hash(raw)}`;

    return yield* locked(
      id,
      Effect.gen(function* () {
        const row = yield* read(id);
        // One-shot consume precedes every code exchange, including retries after interruption.
        yield* store.delete(id).pipe(Effect.uninterruptible);
        const transaction = yield* decodeLogin(row.payload);
        const as = yield* provider;

        const parameters = yield* Effect.try({
          try: () => oauth.validateAuthResponse(as, client, url, transaction.state),
          catch: unauthorized,
        });

        const result = yield* protocol("browser.callback", async (opts) => {
          const response = await oauth.authorizationCodeGrantRequest(
            as,
            client,
            clientAuth,
            parameters,
            redirectUri,
            transaction.verifier,
            { ...opts, additionalParameters: { resource: options.resource } },
          );

          const result = await oauth.processAuthorizationCodeResponse(as, client, response, {
            expectedNonce: transaction.nonce,
            requireIdToken: true,
          });

          await oauth.validateApplicationLevelSignature(as, response, opts);

          return result;
        });

        const saved = yield* credentials(result);

        if (oauth.getValidatedIdTokenClaims(result)?.sub !== saved.subject)
          return yield* unauthorized();
        const session = random();
        yield* write(
          `session:${hash(session)}`,
          saved,
          (yield* Clock.currentTimeMillis) + lifetime * 1000,
        );

        return { session, location: origin + transaction.returnTo };
      }),
    );
  });

  const session = Effect.fn("BrowserSession.session")(function* (raw: string | undefined) {
    const token = yield* accessToken(raw);
    const principal = yield* options.verifyToken(token);

    return {
      subject: principal.subject,
      scopes: principal.scopes,
      issuer: options.issuer,
    };
  });

  const logout = Effect.fn("BrowserSession.logout")(function* (raw: string | undefined) {
    if (!raw) return;
    const id = `session:${hash(raw)}`;
    yield* locked(
      id,
      Effect.gen(function* () {
        const row = yield* store.get(id);
        yield* store.delete(id).pipe(Effect.uninterruptible);

        if (!row) return;
        const saved = yield* decodeCredentials(row.payload);

        if (!saved.refreshToken) return;
        const token = saved.refreshToken;
        // Local deletion is authoritative. Provider revocation is deliberately best effort.
        yield* Effect.gen(function* () {
          const as = yield* provider;
          yield* protocol("browser.revoke", async (opts) =>
            oauth.processRevocationResponse(
              await oauth.revocationRequest(as, client, clientAuth, token, {
                ...opts,
                additionalParameters: { token_type_hint: "refresh_token" },
              }),
            ),
          );
        }).pipe(
          Effect.catch(() =>
            Effect.logWarning("Browser session ended locally; provider revocation failed"),
          ),
        );
      }),
    );
  });

  return {
    login,
    callback,
    session,
    logout,
    accessToken,
    origin,
    // SAFETY: the validated HTTP(S) URL has an absolute pathname beginning with "/".
    callbackPath: callbackUrl.pathname as `/${string}`,
    resource: options.resource,
    issuer: options.issuer,
    cookie: { name: options.cookie.name, lifetime, secure: callbackUrl.protocol === "https:" },
    checkOrigin: (value: string | undefined) =>
      value === origin
        ? Effect.void
        : Effect.fail(new Forbidden({ message: "Cross-origin request rejected" })),
  };
});

export type BrowserSession = Effect.Success<ReturnType<typeof make>>;
