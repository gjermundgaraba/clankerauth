/**
 * The owner's sign-ins: `signIn` keeps one in `~/.config/clankerauth/sign-ins.json` (under
 * `XDG_CONFIG_HOME` when set), and `token` gives a current access token from it, refreshed as it
 * is about to expire. The CLI and every program reading the file share this module, so a refresh
 * by one is the token of all: every change to the file holds its lock, and a process waiting on
 * it reads what the other saved. Node only.
 *
 * A program calling an application takes its token with `token`, then sends it, or has
 * `authorizing` send a current one with each request:
 *
 * ```ts
 * const bearer = yield* Credentials.token({
 *   url: "https://notes.home.example/api/notes",
 *   token: Config.Redacted("NOTES_TOKEN"),
 * });
 * ```
 */
import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import * as oauth from "oauth4webapi";
import lockfile from "proper-lockfile";
import { Clock, Config, Data, Deferred, Effect, Option, Redacted, Schema } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

/**
 * No sign-in to `resource` can give a token: none is kept, or the issuer refused to refresh it.
 * Only the owner can mend it, by running `command`, which `message` names.
 */
export class SignInRequired extends Data.TaggedError("SignInRequired")<{
  readonly resource: string;
  /** The command that signs in again, such as `clankerauth login https://notes.example/`. */
  readonly command: string;
  readonly message: string;
}> {}

/**
 * The sign-in file could not be read, written or locked, or the issuer could not be reached or
 * answered something unusable: `message` says which, for a person.
 */
export class TokenUnavailable extends Data.TaggedError("TokenUnavailable")<{
  readonly message: string;
}> {
  declare readonly cause?: unknown;

  constructor(options: { readonly message: string; readonly cause?: unknown }) {
    super({ message: options.message });
    Object.defineProperty(this, "cause", { value: options.cause });
  }
}

/**
 * A sign-in did not finish: the application, its issuer or the owner's approval failed, as
 * `message` says, for a person.
 */
export class SignInFailed extends Data.TaggedError("SignInFailed")<{
  readonly message: string;
}> {}

/** The issuer's RFC 8414 metadata a sign-in, a refresh and a revocation use, under its RFC names. */
const Server = Schema.Struct({
  issuer: Schema.String,
  authorization_endpoint: Schema.String,
  token_endpoint: Schema.String,
  registration_endpoint: Schema.String,
  revocation_endpoint: Schema.String,
});

type Server = typeof Server.Type;

/**
 * The owner's authorization for one resource, with all a refresh needs: the issuer, and the
 * client the sign-in registered there. The access token lasts fifteen minutes and the refresh
 * token rotates on every use, so the file is rewritten whenever one is refreshed.
 */
export const SignIn = Schema.Struct({
  /** The token audience: a resource identifier, such as `https://notes.home.example/`. */
  resource: Schema.String,
  /** The issuer's origin, `CLANKERAUTH_BASE_URL`: where `/api/owner/<action>` is served. */
  url: Schema.String,
  server: Server,
  clientId: Schema.String,
  /** The scopes granted, `offline_access` among them. */
  scope: Schema.String,
  accessToken: Schema.String,
  refreshToken: Schema.String,
  /** When the access token expires, as an ISO instant. */
  expiresAt: Schema.String,
});

export type SignIn = typeof SignIn.Type;

/** The file: each sign-in, by its resource. */
const SignIns = Schema.Struct({ signIns: Schema.Record(Schema.String, SignIn) });

type SignIns = typeof SignIns.Type;

const SignInsJson = Schema.fromJsonString(SignIns);

const none: SignIns = { signIns: {} };

/** The file's path, read from the environment on every call. */
export const path = () =>
  join(
    process.env["XDG_CONFIG_HOME"] || join(homedir(), ".config"),
    "clankerauth",
    "sign-ins.json",
  );

const causeOf = (error: { readonly message: string; readonly cause?: unknown }) =>
  error.cause instanceof Error ? error.cause.message : error.message;

const failed = (what: string) => (error: { readonly message: string; readonly cause?: unknown }) =>
  new TokenUnavailable({ message: `${what} ${path()}: ${causeOf(error)}`, cause: error });

const hasCode = (code: string) => (error: { readonly cause?: unknown }) =>
  error.cause instanceof Error && "code" in error.cause && error.cause.code === code;

const read = () =>
  Effect.tryPromise(() => readFile(path(), "utf8")).pipe(
    Effect.map((json) => Option.getOrElse(Schema.decodeOption(SignInsJson)(json), () => none)),
    Effect.catchIf(hasCode("ENOENT"), () => Effect.succeed(none)),
    Effect.mapError(failed("Cannot read")),
  );

/** Every sign-in kept; none when there is no file, or one no version of it can be read from. */
export const list = () => Effect.map(read(), ({ signIns }) => Object.values(signIns));

const persist = Effect.fn("Credentials.persist")(
  function* (signIns: SignIns) {
    const file = path();

    if (Object.keys(signIns.signIns).length === 0)
      return yield* Effect.tryPromise(() => rm(file, { force: true }));

    const json = yield* Schema.encodeEffect(SignInsJson)(signIns);
    // why: staged and renamed, so an interrupted write never leaves a refresh token half-saved.
    const staging = `${file}.${randomBytes(6).toString("hex")}`;

    yield* Effect.tryPromise(async () => {
      await mkdir(dirname(file), { recursive: true, mode: 0o700 });
      await writeFile(staging, `${json}\n`, { mode: 0o600 });
      await rename(staging, file);
    }).pipe(Effect.tapError(() => Effect.promise(() => rm(staging, { force: true }))));
  },
  Effect.mapError(failed("Cannot write")),
);

/** Wait this long for another process to let the file go: well past a refresh's deadline. */
const lockRetries = { retries: 150, factor: 1, minTimeout: 100, maxTimeout: 100 };

/** Read the file, write what `change` makes of it, and give what it held before. */
type Save = (change: (signIns: SignIns) => SignIns) => Effect.Effect<SignIns, TokenUnavailable>;

const save: Save = (change) =>
  Effect.flatMap(read(), (before) => Effect.as(persist(change(before)), before));

/**
 * Run `use` holding the file's lock, `sign-ins.json.lock` beside it, given the one way to write
 * the file. Each write reads the file again and changes only its own sign-in, so even one whose
 * lock another process took over, as one stalled past the lock's ten seconds loses it, keeps
 * what that process saved.
 */
const locked = <A, E, R>(use: (save: Save) => Effect.Effect<A, E, R>) =>
  Effect.acquireUseRelease(
    Effect.tryPromise(async () => {
      await mkdir(dirname(path()), { recursive: true, mode: 0o700 });

      return lockfile.lock(path(), {
        realpath: false,
        retries: lockRetries,
        update: 1000,
        // why: throwing here would crash the program, and the writes need the lock no longer.
        onCompromised: () => undefined,
      });
    }).pipe(Effect.mapError(failed("Cannot lock"))),
    () => use(save),
    (release) => Effect.promise(() => release().catch(() => undefined)),
  );

/** How long one request to an application or an issuer may take: well under a lock's wait. */
const requestDeadline = 10_000;

const requestOptions = (url: string | URL) => ({
  // why: plain HTTP only for an address named with `http:`, such as one on loopback.
  [oauth.allowInsecureRequests]: new URL(url).protocol === "http:",
  signal: AbortSignal.timeout(requestDeadline),
});

/** The RFC 9728 check's failure: the metadata names another resource than the one asked for. */
const NamedElsewhere = Schema.Struct({
  attribute: Schema.Literal("resource"),
  body: Schema.Struct({ resource: Schema.String }),
});

/** Why `oauth4webapi` failed, for a person. */
const reason = (error: Error) => {
  if (error instanceof oauth.ResponseBodyError || error instanceof oauth.AuthorizationResponseError)
    return [error.error, error.error_description].filter(Boolean).join(": ");

  if (error instanceof oauth.OperationProcessingError) {
    const named = Schema.decodeUnknownOption(NamedElsewhere)(error.cause);

    if (Option.isSome(named))
      return `it publishes the resource ${named.value.body.resource}: sign in to that address`;

    if (error.cause instanceof Response) return `${error.message} (HTTP ${error.cause.status})`;
  }

  return error.cause instanceof Error ? `${error.message} (${error.cause.message})` : error.message;
};

const refreshScope = "offline_access";

/** The scopes of `scope` a sign-in asks for, beside `offline_access`, which every one asks for. */
const asked = (scope: string) =>
  scope.split(" ").filter((named) => named !== "" && named !== refreshScope);

/** `url` as a resource is matched against: without its query or fragment. */
const located = (url: string | URL) =>
  Effect.try({
    try: () => {
      const parsed = new URL(url);
      parsed.search = "";
      parsed.hash = "";

      return parsed;
    },
    catch: (cause) => new TokenUnavailable({ message: `${String(url)} is no URL`, cause }),
  });

const holds = (resource: string, url: URL) =>
  url.href === resource || url.href.startsWith(resource.endsWith("/") ? resource : `${resource}/`);

/** The sign-in whose resource holds `url`, the most specific when several do. */
const signInFor = (signIns: SignIns, url: URL) =>
  Object.values(signIns.signIns)
    .filter((signIn) => holds(signIn.resource, url))
    .toSorted((first, second) => second.resource.length - first.resource.length)
    .at(0);

const held = Effect.fn("Credentials.held")(function* (url: URL) {
  const signIn = signInFor(yield* read(), url);

  if (signIn !== undefined) return signIn;
  const resource = new URL("/", url).href;
  const command = `clankerauth login ${resource}`;

  return yield* new SignInRequired({
    resource,
    command,
    message: `Not signed in to ${resource}: run \`${command}\` first.`,
  });
});

const signInOf = (
  grant: Omit<SignIn, "accessToken" | "refreshToken" | "expiresAt">,
  tokens: oauth.TokenEndpointResponse,
  refreshToken: string,
  now: number,
): SignIn => ({
  resource: grant.resource,
  url: grant.url,
  server: grant.server,
  clientId: grant.clientId,
  scope: tokens.scope ?? grant.scope,
  accessToken: tokens.access_token,
  refreshToken,
  expiresAt: new Date(now + (tokens.expires_in ?? 0) * 1000).toISOString(),
});

const refresh = (signIn: SignIn) =>
  Effect.tryPromise({
    try: async () =>
      oauth.processRefreshTokenResponse(
        signIn.server,
        { client_id: signIn.clientId },
        await oauth.refreshTokenGrantRequest(
          signIn.server,
          { client_id: signIn.clientId },
          oauth.None(),
          signIn.refreshToken,
          { additionalParameters: { resource: signIn.resource }, ...requestOptions(signIn.url) },
        ),
      ),
    catch: (error) => {
      if (
        !(error instanceof oauth.ResponseBodyError) ||
        (error.status !== 400 && error.status !== 401)
      )
        return new TokenUnavailable({
          message: `Refresh: ${error instanceof Error ? reason(error) : String(error)}`,
          cause: error,
        });

      const scopes = asked(signIn.scope);

      const command = [
        `clankerauth login ${signIn.resource}`,
        ...(scopes.length === 0 ? [] : [`--scope "${scopes.join(" ")}"`]),
      ].join(" ");

      return new SignInRequired({
        resource: signIn.resource,
        command,
        message: `Refresh: ${reason(error)}. Run \`${command}\` again.`,
      });
    },
  });

/** A token is refreshed this long before it expires, so none expires on its way. */
const refreshMargin = 60_000;

const current = (signIn: SignIn) =>
  Effect.map(Clock.currentTimeMillis, (now) =>
    Date.parse(signIn.expiresAt) - now > refreshMargin
      ? Option.some(Redacted.make(signIn.accessToken))
      : Option.none(),
  );

const accessToken = Effect.fn("Credentials.accessToken")(function* (url: URL) {
  const unlocked = yield* current(yield* held(url));

  if (Option.isSome(unlocked)) return unlocked.value;

  return yield* locked((save) =>
    Effect.gen(function* () {
      const signIn = yield* held(url);
      const refreshedMeanwhile = yield* current(signIn);

      if (Option.isSome(refreshedMeanwhile)) return refreshedMeanwhile.value;

      const tokens = yield* refresh(signIn);
      const now = yield* Clock.currentTimeMillis;
      const refreshed = signInOf(signIn, tokens, tokens.refresh_token ?? signIn.refreshToken, now);

      yield* save(({ signIns }) =>
        // why: a sign-in another process changed meanwhile, having taken the lock over, is newer.
        signIns[signIn.resource]?.refreshToken === signIn.refreshToken
          ? { signIns: { ...signIns, [signIn.resource]: refreshed } }
          : { signIns },
      );

      return Redacted.make(refreshed.accessToken);
    }).pipe(
      // why: the issuer rotates the refresh token as it answers, so an interrupted refresh would lose the only one left.
      Effect.uninterruptible,
    ),
  );
});

export interface TokenOptions {
  /**
   * Where the program calls the application, or any address under its resource: the sign-in
   * used is the one whose resource holds this URL, the most specific when several do.
   */
  readonly url: string | URL;
  /**
   * A bearer token the environment may give, an API key or an access token, returned instead
   * of any sign-in when it is set: `Config.Redacted("NOTES_TOKEN")`.
   */
  readonly token?: Config.Config<Redacted.Redacted<string>>;
}

/**
 * A program's bearer token for the application at `options.url`: the environment's when it
 * gives one, so the program runs unattended, and otherwise the owner's sign-in whose resource
 * holds the URL, which `clankerauth login <url>` keeps and this refreshes. Ask again for each
 * call, or each run: a token is never within a minute of expiring.
 */
export const token = Effect.fn("Credentials.token")(function* (options: TokenOptions) {
  if (options.token !== undefined) {
    const given = yield* Config.option(options.token).pipe(
      Effect.mapError(
        (error) =>
          new TokenUnavailable({ message: `The token given is unreadable: ${error.message}` }),
      ),
    );

    if (Option.isSome(given)) return given.value;
  }

  return yield* accessToken(yield* located(options.url));
});

/**
 * A client sending the bearer token `token` gives for `options` with each request, so a long run
 * is refreshed as it goes: an effect-actions client's `transformClient`, whose methods then fail
 * with `SignInRequired` and `TokenUnavailable` too.
 *
 * ```ts
 * const notes = yield* ActionHttp.client(NotesHttp, {
 *   baseUrl: "https://notes.home.example",
 *   transformClient: Credentials.authorizing({ url: "https://notes.home.example/" }),
 * });
 * ```
 */
export const authorizing = (options: TokenOptions) => (client: HttpClient.HttpClient) =>
  HttpClient.mapRequestEffect(client, (request) =>
    Effect.map(token(options), (bearer) => HttpClientRequest.bearerToken(request, bearer)),
  );

const step = <A>(what: string, run: () => Promise<A>) =>
  Effect.tryPromise({
    try: run,
    catch: (error) =>
      new SignInFailed({
        message: `${what}: ${error instanceof Error ? reason(error) : String(error)}`,
      }),
  });

const discover = Effect.fn("Credentials.discover")(function* (url: string) {
  const resource = yield* Effect.try({
    try: () => new URL(url),
    catch: () => new SignInFailed({ message: `${url} is no URL, such as https://notes.example/` }),
  });

  const what = `Discovery at ${resource.origin}`;

  const metadata = yield* step(what, async () =>
    oauth.processResourceDiscoveryResponse(
      resource,
      await oauth.resourceDiscoveryRequest(resource, requestOptions(resource)),
    ),
  );

  const [named] = metadata.authorization_servers ?? [];

  if (named === undefined)
    return yield* new SignInFailed({ message: `${what}: it names no authorization server` });

  const issuer = yield* Effect.try({
    try: () => new URL(named),
    catch: () =>
      new SignInFailed({ message: `${what}: its authorization server ${named} is no URL` }),
  });

  const server = yield* step(what, async () =>
    oauth.processDiscoveryResponse(
      issuer,
      await oauth.discoveryRequest(issuer, { algorithm: "oauth2", ...requestOptions(issuer) }),
    ),
  );

  return {
    resource: metadata.resource,
    scopes: metadata.scopes_supported ?? [],
    server: yield* Schema.decodeUnknownEffect(Server)(server).pipe(
      Effect.mapError(
        (error) =>
          new SignInFailed({ message: `${what}: the issuer lacks an endpoint (${error.message})` }),
      ),
    ),
  };
});

// why: loopback redirects match without their port (RFC 8252), so one registration serves all.
const registeredRedirect = "http://127.0.0.1/callback";

const register = (server: Server) =>
  step("Registration", async () =>
    oauth.processDynamicClientRegistrationResponse(
      await oauth.dynamicClientRegistrationRequest(
        server,
        {
          client_name: "clankerauth CLI",
          redirect_uris: [registeredRedirect],
          application_type: "native",
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
        },
        requestOptions(server.issuer),
      ),
    ),
  ).pipe(Effect.map((registered) => registered.client_id));

const page =
  '<!doctype html><meta charset="utf-8"><title>clankerauth</title><p>Return to the terminal.</p>';

const listen = Effect.acquireRelease(
  Effect.gen(function* () {
    const received = yield* Deferred.make<URLSearchParams>();

    const server: HttpServer = createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");

      if (url.pathname !== "/callback") {
        response.writeHead(404).end();

        return;
      }

      response.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(page);
      Deferred.doneUnsafe(received, Effect.succeed(url.searchParams));
    });

    const port = yield* Effect.callback<number, SignInFailed>((resume) => {
      server.once("error", (error) =>
        resume(
          Effect.fail(
            new SignInFailed({ message: `Cannot listen for the redirect: ${error.message}` }),
          ),
        ),
      );
      server.listen(0, "127.0.0.1", () =>
        // SAFETY: a listening TCP server's address is an AddressInfo, not a pipe's string.
        resume(Effect.succeed((server.address() as AddressInfo).port)),
      );
    });

    return { server, port, received };
  }),
  ({ server }) =>
    Effect.sync(() => {
      server.closeAllConnections();
      server.close();
    }),
);

const authorizationPage = Effect.fn("Credentials.authorizationPage")(function* (
  server: Server,
  clientId: string,
  redirectUri: string,
  scope: string,
  resource: string,
) {
  const verifier = oauth.generateRandomCodeVerifier();
  const state = oauth.generateRandomState();
  const url = new URL(server.authorization_endpoint);

  url.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope,
    resource,
    code_challenge: yield* Effect.promise(() => oauth.calculatePKCECodeChallenge(verifier)),
    code_challenge_method: "S256",
    state,
  }).toString();

  return { url, state, verifier };
});

const exchangeCode = (
  server: Server,
  clientId: string,
  callback: URLSearchParams,
  expected: { readonly state: string; readonly verifier: string; readonly redirectUri: string },
  resource: string,
) =>
  step("Sign-in", async () => {
    const client = { client_id: clientId };
    const parameters = oauth.validateAuthResponse(server, client, callback, expected.state);

    return oauth.processAuthorizationCodeResponse(
      server,
      client,
      await oauth.authorizationCodeGrantRequest(
        server,
        client,
        oauth.None(),
        parameters,
        expected.redirectUri,
        expected.verifier,
        { additionalParameters: { resource }, ...requestOptions(server.issuer) },
      ),
    );
  });

const revoke = (signIn: SignIn) =>
  Effect.ignore(
    Effect.tryPromise(async () =>
      oauth.processRevocationResponse(
        await oauth.revocationRequest(
          signIn.server,
          { client_id: signIn.clientId },
          oauth.None(),
          signIn.refreshToken,
          {
            additionalParameters: { token_type_hint: "refresh_token" },
            ...requestOptions(signIn.url),
          },
        ),
      ),
    ),
  );

export interface SignInOptions {
  /** The scopes to ask for, space-separated; every scope the resource publishes when left out. */
  readonly scope?: string | undefined;
  /**
   * Show the owner the issuer's approval page, such as by printing its URL. The sign-in then
   * waits up to five minutes for the approval.
   */
  readonly approve: (page: URL) => Effect.Effect<void>;
}

/**
 * Sign in as the issuer's owner to the resource `url` identifies, read from its
 * `/.well-known/oauth-protected-resource`, and keep the sign-in, replacing and revoking any to
 * that resource. The issuer is the one the resource names; the sign-in registers a native OAuth
 * client there, asks for `offline_access` beside the scopes, and listens for the redirect on a
 * loopback port.
 */
export const signIn = Effect.fn("Credentials.signIn")(function* (
  url: string,
  options: SignInOptions,
) {
  const { resource, scopes, server } = yield* discover(url);
  const scope = [...asked(options.scope ?? scopes.join(" ")), refreshScope].join(" ");
  const clientId = yield* register(server);
  const { port, received } = yield* listen;
  const redirectUri = `http://127.0.0.1:${port}/callback`;

  const approval = yield* authorizationPage(server, clientId, redirectUri, scope, resource);

  yield* options.approve(approval.url);

  const callback = yield* Deferred.await(received).pipe(
    Effect.timeoutOrElse({
      duration: "5 minutes",
      orElse: () =>
        Effect.fail(
          new SignInFailed({ message: "Sign-in: nobody approved it within five minutes" }),
        ),
    }),
  );

  const tokens = yield* exchangeCode(
    server,
    clientId,
    callback,
    { ...approval, redirectUri },
    resource,
  );

  if (tokens.refresh_token === undefined)
    return yield* new SignInFailed({ message: "Sign-in: the issuer issued no refresh token" });

  const kept = signInOf(
    { resource, url: new URL(server.issuer).origin, server, clientId, scope },
    tokens,
    tokens.refresh_token,
    yield* Clock.currentTimeMillis,
  );

  const before = yield* locked((save) =>
    save(({ signIns }) => ({ signIns: { ...signIns, [resource]: kept } })),
  );

  const replaced = before.signIns[resource];

  if (replaced !== undefined) yield* revoke(replaced);

  return { url: kept.url, resource, scope: kept.scope };
}, Effect.scoped);

/**
 * Forget the sign-in whose resource holds `url`, or every one, holding the file's lock so a
 * refresh never slips between, then revoke it. A sign-in is forgotten even when the issuer does
 * not answer its revocation.
 */
export const signOut = Effect.fn("Credentials.signOut")(function* (url?: string | URL) {
  const target = url === undefined ? undefined : yield* located(url);

  const leaving = (signIns: SignIns) =>
    target === undefined
      ? Object.values(signIns.signIns)
      : Option.toArray(Option.fromNullishOr(signInFor(signIns, target)));

  const before = yield* locked((save) =>
    save((signIns) => {
      const left = leaving(signIns);

      return {
        signIns: Object.fromEntries(
          Object.entries(signIns.signIns).filter(([kept]) =>
            left.every((signIn) => signIn.resource !== kept),
          ),
        ),
      };
    }),
  );

  const left = leaving(before);

  yield* Effect.forEach(left, revoke, { concurrency: "unbounded", discard: true });

  return { signedOut: left.length > 0 };
});
