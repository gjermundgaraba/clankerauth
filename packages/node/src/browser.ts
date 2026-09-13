import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import * as oauth from "oauth4webapi";
import { AuthError } from "./errors.ts";
import type { Principal } from "./verify.ts";

/** Sealed rows keyed by an opaque id. One process owns the store; the session serializes work per id. */
export interface BrowserSessionStore {
  readonly get: (
    id: string,
  ) => Promise<{ readonly payload: string; readonly expires: number } | undefined>;
  readonly put: (id: string, payload: string, expires: number) => Promise<void>;
  readonly delete: (id: string) => Promise<void>;
  /** Remove rows whose `expires` is at or before `now`. */
  readonly sweep: (now: number) => Promise<void>;
}

export interface BrowserSessionOptions {
  /** Issuer identifier, for example `https://auth.internal/api/auth`. */
  readonly issuer: string;
  /** A confidential client registered with redirect `<origin>/auth/callback`. */
  readonly clientId: string;
  readonly clientSecret: string;
  /** The origin the browser uses; cookies and redirects bind to it. */
  readonly origin: string;
  /** Exact audience URL the browser session obtains tokens for. */
  readonly resource: string;
  /** Resource scopes to request. `openid` and `offline_access` are added. */
  readonly scopes: readonly string[];
  /** At least 32 characters. Derives the key that seals stored credentials. */
  readonly secret: string;
  readonly store: BrowserSessionStore;
  /** Cookie name prefix; `<name>_session` and `<name>_login` are set. */
  readonly cookie: { readonly name: string; readonly lifetime?: number };
  /** Verifies access tokens the issuer returns, usually a verifier's `verifyToken`. */
  readonly verifyToken: (token: string) => Promise<Principal>;
  /** Observes failures that are not user outcomes: outages, malformed issuer responses. */
  readonly onFailure?: (operation: string, error: unknown) => void | Promise<void>;
}

/**
 * Browser login as a confidential client. Route `POST /auth/login`, `GET /auth/callback`,
 * `GET /auth/session` and `POST /auth/logout` to the handlers; authenticate cookie-bearing
 * requests with `accessToken`.
 */
export interface BrowserSession {
  readonly login: (request: Request) => Promise<Response>;
  readonly callback: (request: Request) => Promise<Response>;
  readonly session: (request: Request) => Promise<Response>;
  readonly logout: (request: Request) => Promise<Response>;
  /** Whether the request carries this session's cookie, before any verification. */
  readonly hasCookie: (request: Request) => boolean;
  /** A current access token for the request's session, refreshing when needed. */
  readonly accessToken: (request: Request) => Promise<string>;
}

const defaultLifetime = 30 * 24 * 60 * 60;
const transactionLifetime = 600;
const maxLoginBody = 16 * 1024;

class Failure extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "BrowserSessionFailure";
    this.status = status;
  }
}

interface Credentials {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly accessExpires: number;
  readonly subject: string;
  readonly refreshBlocked: boolean;
}
interface Login {
  readonly verifier: string;
  readonly state: string;
  readonly nonce: string;
  readonly returnTo: string;
}

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const random = () => randomBytes(32).toString("base64url");
const cookieValue = (request: Request, name: string) =>
  request.headers
    .get("cookie")
    ?.split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1);
const isString = (value: unknown): value is string => typeof value === "string";
const decodeCredentials = (value: unknown): Credentials => {
  const record = (typeof value === "object" && value !== null ? value : {}) as Record<
    string,
    unknown
  >;
  if (
    !isString(record.accessToken) ||
    !(record.refreshToken === undefined || isString(record.refreshToken)) ||
    typeof record.accessExpires !== "number" ||
    !isString(record.subject) ||
    typeof record.refreshBlocked !== "boolean"
  )
    throw new Failure(401, "Sign in required");
  return {
    accessToken: record.accessToken,
    refreshToken: record.refreshToken,
    accessExpires: record.accessExpires,
    subject: record.subject,
    refreshBlocked: record.refreshBlocked,
  };
};
const decodeLogin = (value: unknown): Login => {
  const record = (typeof value === "object" && value !== null ? value : {}) as Record<
    string,
    unknown
  >;
  if (
    !isString(record.verifier) ||
    !isString(record.state) ||
    !isString(record.nonce) ||
    !isString(record.returnTo)
  )
    throw new Failure(401, "Login expired; sign in again");
  return {
    verifier: record.verifier,
    state: record.state,
    nonce: record.nonce,
    returnTo: record.returnTo,
  };
};

const loginInput = async (request: Request): Promise<{ readonly returnTo: string }> => {
  const reader = request.body?.getReader();
  if (!reader) throw new Failure(400, "Invalid login request");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxLoginBody) {
        await reader.cancel();
        throw new Failure(413, "Login request too large");
      }
      chunks.push(chunk.value);
    }
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const returnTo =
      typeof parsed === "object" && parsed !== null
        ? (parsed as Record<string, unknown>).returnTo
        : undefined;
    if (!isString(returnTo)) throw new Failure(400, "Invalid login request");
    return { returnTo };
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new Failure(400, "Invalid login request");
  } finally {
    reader.releaseLock();
  }
};

export function createBrowserSession(options: BrowserSessionOptions): BrowserSession {
  if (options.secret.length < 32) throw new Error("Browser session secret needs 32 characters");
  const origin = new URL(options.origin).origin;
  const issuer = new URL(options.issuer);
  const redirectUri = `${origin}/auth/callback`;
  const secure = new URL(origin).protocol === "https:";
  const lifetime = options.cookie.lifetime ?? defaultLifetime;
  const sessionCookie = `${options.cookie.name}_session`;
  const transactionCookie = `${options.cookie.name}_login`;
  const scope = ["openid", "offline_access", ...options.scopes].join(" ");
  const report = async (operation: string, error: unknown) => {
    await options.onFailure?.(operation, error);
  };
  const key = createHash("sha256").update(options.secret).digest();
  const seal = (value: Credentials | Login) => {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url");
  };
  const open = (value: string): unknown => {
    const bytes = Buffer.from(value, "base64url");
    const cipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
    cipher.setAuthTag(bytes.subarray(12, 28));
    return JSON.parse(
      Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString("utf8"),
    );
  };
  const read = async (id: string) => {
    const row = await options.store.get(id);
    if (!row) return undefined;
    if (row.expires <= Date.now()) {
      await options.store.delete(id);
      return undefined;
    }
    return row;
  };
  const write = (id: string, value: Credentials | Login, expires: number) =>
    options.store.put(id, seal(value), expires);
  const locks = new Map<string, Promise<void>>();
  const locked = async <A>(id: string, action: () => Promise<A>): Promise<A> => {
    const previous = locks.get(id) ?? Promise.resolve();
    const { promise: pending, resolve: release } = Promise.withResolvers<void>();
    const tail = previous.then(() => pending);
    locks.set(id, tail);
    await previous;
    try {
      return await action();
    } finally {
      release();
      if (locks.get(id) === tail) locks.delete(id);
    }
  };
  const requestOptions = () => ({
    signal: AbortSignal.timeout(5_000),
    [oauth.allowInsecureRequests]:
      issuer.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(issuer.hostname),
  });
  let discovery: Promise<oauth.AuthorizationServer> | undefined;
  const provider = () =>
    (discovery ??= oauth
      .discoveryRequest(issuer, requestOptions())
      .then((response) => oauth.processDiscoveryResponse(issuer, response))
      .catch(async (error: unknown) => {
        discovery = undefined;
        await report("browser.discovery", error);
        throw new Failure(503, "Authentication provider unavailable");
      }));
  const client: oauth.Client = { client_id: options.clientId };
  const clientAuth = oauth.ClientSecretBasic(options.clientSecret);
  const cookie = (name: string, value: string, age: number) =>
    `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${secure ? "; Secure" : ""}`;
  const sameOrigin = (request: Request) => {
    if (request.headers.get("origin") !== origin)
      throw new Failure(403, "Cross-origin request rejected");
  };
  const credentials = async (
    result: oauth.TokenEndpointResponse,
    old?: Credentials,
  ): Promise<Credentials> => {
    if (
      result.token_type.toLowerCase() !== "bearer" ||
      !result.expires_in ||
      result.expires_in <= 0
    )
      throw new Failure(401, "Invalid OAuth token response");
    let verified: Principal;
    try {
      verified = await options.verifyToken(result.access_token);
    } catch (error) {
      if (error instanceof AuthError && error.code !== "unavailable")
        throw new Failure(401, "Sign in required");
      throw new Failure(503, "Authentication unavailable");
    }
    if (old && old.subject !== verified.subject) throw new Failure(401, "OAuth account changed");
    const refreshToken = result.refresh_token ?? old?.refreshToken;
    const next: Credentials = {
      accessToken: result.access_token,
      accessExpires: Date.now() + result.expires_in * 1000,
      subject: verified.subject,
      refreshBlocked: false,
    };
    return refreshToken ? { ...next, refreshToken } : next;
  };
  const currentToken = async (request: Request): Promise<string> => {
    const raw = cookieValue(request, sessionCookie);
    if (!raw) throw new Failure(401, "Sign in required");
    const id = `session:${hash(raw)}`;
    return locked(id, async () => {
      const row = await read(id);
      if (!row) throw new Failure(401, "Sign in required");
      const saved = decodeCredentials(open(row.payload));
      if (saved.accessExpires > Date.now() + 30_000) return saved.accessToken;
      if (!saved.refreshToken || saved.refreshBlocked) {
        await options.store.delete(id);
        throw new Failure(401, "Sign in required");
      }
      const as = await provider();
      // Persist before sending: a timeout or restart must not replay a possibly consumed credential.
      await write(id, { ...saved, refreshBlocked: true }, row.expires);
      try {
        const response = await oauth.refreshTokenGrantRequest(
          as,
          client,
          clientAuth,
          saved.refreshToken,
          { ...requestOptions(), additionalParameters: { resource: options.resource } },
        );
        const result = await oauth.processRefreshTokenResponse(as, client, response);
        if (result.id_token)
          await oauth.validateApplicationLevelSignature(as, response, requestOptions());
        const next = await credentials(result, saved);
        const identity = oauth.getValidatedIdTokenClaims(result);
        if (identity && identity.sub !== next.subject)
          throw new Failure(401, "OAuth account mismatch");
        await write(id, next, row.expires);
        return next.accessToken;
      } catch (error) {
        if (
          !(error instanceof Failure) &&
          !(error instanceof oauth.ResponseBodyError && error.error === "invalid_grant")
        )
          await report("browser.refresh", error);
        await options.store.delete(id);
        throw new Failure(401, "Sign in required");
      }
    }).catch(async (error: unknown) => {
      if (error instanceof Failure) throw error;
      await report("browser.accessToken", error);
      throw new Failure(503, "Authentication unavailable");
    });
  };
  const respond = async (operation: string, action: () => Promise<Response>): Promise<Response> => {
    try {
      return await action();
    } catch (error) {
      if (!(error instanceof Failure) && !(error instanceof oauth.AuthorizationResponseError))
        await report(`browser.${operation}`, error);
      const status =
        error instanceof Failure
          ? error.status
          : error instanceof oauth.AuthorizationResponseError ||
              error instanceof oauth.OperationProcessingError ||
              error instanceof oauth.ResponseBodyError
            ? 401
            : 503;
      if (operation === "callback")
        return new Response(null, {
          status: 302,
          headers: {
            location: `${origin}/?auth_error=${status === 503 ? "unavailable" : "login_failed"}`,
            "set-cookie": cookie(transactionCookie, "", 0),
          },
        });
      return Response.json(
        {
          error:
            error instanceof Failure
              ? error.message
              : status === 401
                ? "Login failed; sign in again"
                : "Authentication unavailable",
        },
        { status },
      );
    }
  };
  const operation =
    (name: string, action: (request: Request) => Promise<Response>) =>
    async (request: Request): Promise<Response> => {
      const response = await respond(name, () => action(request));
      response.headers.set("referrer-policy", "no-referrer");
      response.headers.set("cache-control", "no-store");
      return response;
    };
  const login = operation("login", async (request) => {
    sameOrigin(request);
    const input = await loginInput(request);
    let target: URL;
    try {
      target = new URL(input.returnTo, origin);
    } catch {
      throw new Failure(400, "Invalid return destination");
    }
    if (
      !input.returnTo.startsWith("/") ||
      target.origin !== origin ||
      target.pathname.startsWith("/auth/")
    )
      throw new Failure(400, "Invalid return destination");
    const as = await provider();
    if (!as.authorization_endpoint) {
      await report("browser.discovery", new Error("Authorization endpoint unavailable"));
      throw new Failure(503, "Authorization endpoint unavailable");
    }
    const raw = random();
    const transaction: Login = {
      verifier: oauth.generateRandomCodeVerifier(),
      state: oauth.generateRandomState(),
      nonce: oauth.generateRandomNonce(),
      returnTo: target.pathname + target.search + target.hash,
    };
    const authorization = new URL(as.authorization_endpoint);
    authorization.search = new URLSearchParams({
      client_id: options.clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope,
      resource: options.resource,
      state: transaction.state,
      nonce: transaction.nonce,
      code_challenge: await oauth.calculatePKCECodeChallenge(transaction.verifier),
      code_challenge_method: "S256",
    }).toString();
    await options.store.sweep(Date.now());
    await write(`login:${hash(raw)}`, transaction, Date.now() + transactionLifetime * 1000);
    return Response.json(
      { url: authorization.href },
      { headers: { "set-cookie": cookie(transactionCookie, raw, transactionLifetime) } },
    );
  });
  const callback = operation("callback", async (request) => {
    const url = new URL(request.url);
    if (
      url.searchParams.getAll("iss").length !== 1 ||
      url.searchParams.get("iss") !== options.issuer
    )
      throw new Failure(401, "Invalid authorization issuer");
    const raw = cookieValue(request, transactionCookie);
    if (!raw) throw new Failure(401, "Login expired; sign in again");
    const id = `login:${hash(raw)}`;
    return locked(id, async () => {
      const row = await read(id);
      if (!row) throw new Failure(401, "Login expired; sign in again");
      await options.store.delete(id);
      const transaction = decodeLogin(open(row.payload));
      const as = await provider();
      const parameters = oauth.validateAuthResponse(as, client, url, transaction.state);
      const response = await oauth.authorizationCodeGrantRequest(
        as,
        client,
        clientAuth,
        parameters,
        redirectUri,
        transaction.verifier,
        { ...requestOptions(), additionalParameters: { resource: options.resource } },
      );
      const result = await oauth.processAuthorizationCodeResponse(as, client, response, {
        expectedNonce: transaction.nonce,
        requireIdToken: true,
      });
      await oauth.validateApplicationLevelSignature(as, response, requestOptions());
      const saved = await credentials(result);
      if (oauth.getValidatedIdTokenClaims(result)?.sub !== saved.subject)
        throw new Failure(401, "OAuth account mismatch");
      const session = random();
      await write(`session:${hash(session)}`, saved, Date.now() + lifetime * 1000);
      const headers = new Headers({ location: origin + transaction.returnTo });
      headers.append("set-cookie", cookie(sessionCookie, session, lifetime));
      headers.append("set-cookie", cookie(transactionCookie, "", 0));
      return new Response(null, { status: 302, headers });
    });
  });
  const session = operation("session", async (request) => {
    const token = await currentToken(request);
    let principal: Principal;
    try {
      principal = await options.verifyToken(token);
    } catch (error) {
      if (error instanceof AuthError && error.code !== "unavailable")
        throw new Failure(401, "Sign in required");
      throw new Failure(503, "Authentication unavailable");
    }
    return Response.json({
      authenticated: true,
      subject: principal.subject,
      scopes: principal.scopes,
      issuer: options.issuer,
    });
  });
  const logout = operation("logout", async (request) => {
    sameOrigin(request);
    const raw = cookieValue(request, sessionCookie);
    if (raw) {
      const id = `session:${hash(raw)}`;
      await locked(id, async () => {
        const row = await read(id);
        await options.store.delete(id);
        if (!row) return;
        const saved = decodeCredentials(open(row.payload));
        if (!saved.refreshToken) return;
        try {
          await oauth.processRevocationResponse(
            await oauth.revocationRequest(
              await provider(),
              client,
              clientAuth,
              saved.refreshToken,
              {
                ...requestOptions(),
                additionalParameters: { token_type_hint: "refresh_token" },
              },
            ),
          );
        } catch (error) {
          // Local invalidation is authoritative even when revocation is unavailable.
          if (!(error instanceof Failure)) await report("browser.revoke", error);
        }
      });
    }
    return new Response(null, {
      status: 204,
      headers: { "set-cookie": cookie(sessionCookie, "", 0) },
    });
  });
  return {
    login,
    callback,
    session,
    logout,
    hasCookie: (request) => cookieValue(request, sessionCookie) !== undefined,
    accessToken: async (request) => {
      try {
        return await currentToken(request);
      } catch (error) {
        if (error instanceof Failure)
          throw new AuthError(error.status === 503 ? "unavailable" : "unauthorized", error.message);
        throw error;
      }
    },
  };
}
