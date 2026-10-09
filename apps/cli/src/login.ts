import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Deferred, Effect, Match, Option } from "effect";
import {
  readCredentials,
  removeCredentials,
  saveSignIn,
  writeCredentials,
  type Credentials,
  type SignIn,
} from "./credentials.ts";
import { discover, OAuthError, register, revoke, token, type Tokens } from "./oauth.ts";

/** The issuer's own resource, administration: its origin root. */
export const administrationOf = (url: string) => new URL("/", url).href;

/** A sign-in asks for a refresh token too, so it lasts while it is used. */
const withRefresh = (scope: string) =>
  scope.split(" ").includes("offline_access") ? scope : `${scope} offline_access`;

/** The command that signs in to `resource` again, with the scopes it was granted. */
const loginAgain = (url: string, { resource, scope }: SignIn) => {
  if (resource === administrationOf(url)) return `clankerauth login ${url}`;

  const asked = scope
    .split(" ")
    .filter((granted) => granted !== "offline_access")
    .join(" ");

  return `clankerauth login ${url} --resource ${resource} --scope "${asked}"`;
};

/** The redirect a registration names; a sign-in adds the port it listens on. */
const registeredRedirect = "http://127.0.0.1/callback";

/** How long a sign-in waits for the owner to approve it in the browser. */
const approvalWindow = "5 minutes";

const expiry = (tokens: Tokens) => new Date(Date.now() + tokens.expires_in * 1000).toISOString();

/** What the callback page tells the browser; the terminal has the details. */
const page = (heading: string) =>
  `<!doctype html><meta charset="utf-8"><title>clankerauth</title><p>${heading}</p>`;

/** The query a browser brings back to the loopback listener. */
interface Callback {
  readonly code: string | null;
  readonly state: string | null;
  readonly iss: string | null;
  readonly error: string | null;
  readonly errorDescription: string | null;
}

/** Listen on a free loopback port for the one request the authorization redirect makes. */
const listen = Effect.acquireRelease(
  Effect.gen(function* () {
    const received = yield* Deferred.make<Callback>();

    const server: Server = createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");

      if (url.pathname !== "/callback") {
        response.writeHead(404).end();

        return;
      }

      const query = url.searchParams;

      response
        .writeHead(200, { "content-type": "text/html; charset=utf-8" })
        .end(
          page(
            query.has("code")
              ? "Signed in. You can close this tab."
              : "Sign-in failed. The terminal says why.",
          ),
        );
      Deferred.doneUnsafe(
        received,
        Effect.succeed({
          code: query.get("code"),
          state: query.get("state"),
          iss: query.get("iss"),
          error: query.get("error"),
          errorDescription: query.get("error_description"),
        }),
      );
    });

    const port = yield* Effect.callback<number, OAuthError>((resume) => {
      server.once("error", (error) =>
        resume(
          Effect.fail(
            new OAuthError({ message: `Cannot listen for the redirect: ${error.message}` }),
          ),
        ),
      );
      server.listen(0, "127.0.0.1", () =>
        // SAFETY: a TCP listener's address is an AddressInfo once it listens; only a pipe's
        // is a string, and only a closed server's is null.
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

/** Open `url` in the default browser, if the platform has a way to; never fails. */
const openBrowser = (url: string) =>
  Effect.sync(() => {
    const [command, ...args] = Match.value(process.platform).pipe(
      Match.when("darwin", () => ["open", url]),
      Match.when("win32", () => ["cmd", "/c", "start", "", url]),
      Match.orElse(() => ["xdg-open", url]),
    );

    try {
      spawn(command ?? "open", args, { stdio: "ignore", detached: true })
        .on("error", () => {})
        .unref();
    } catch {
      // The URL is printed too, so a missing opener costs nothing.
    }
  });

/**
 * Sign in to the issuer at `url` as its owner, for `resource`, administration when none:
 * discover the issuer, register this CLI once per issuer, send the owner to approve in the
 * browser, and keep the tokens beside the sign-ins to other resources. What it prints on
 * stderr is for the person; stdout gets only the result.
 */
export const login = Effect.fn("Cli.login")(function* (
  url: string,
  target: Option.Option<string>,
  asked: string,
  browser: boolean,
) {
  const origin = new URL(url).origin;
  const discovered = yield* discover(origin);
  const { server } = discovered;
  const resource = Option.getOrElse(target, () => discovered.resource);
  const previous = Option.filter(yield* readCredentials(), (kept) => kept.url === origin);

  const clientId = yield* Option.match(previous, {
    onSome: (kept) => Effect.succeed(kept.clientId),
    onNone: () => register(server, registeredRedirect),
  });

  const { port, received } = yield* listen;
  const redirectUri = `http://127.0.0.1:${port}/callback`;
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(16).toString("base64url");
  const scope = withRefresh(asked);

  const authorization = new URL(server.authorization_endpoint);

  authorization.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope,
    resource,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state,
  }).toString();

  yield* Effect.sync(() =>
    process.stderr.write(`Approve the sign-in in your browser:\n\n  ${authorization.href}\n\n`),
  );

  if (browser) yield* openBrowser(authorization.href);

  const callback = yield* Deferred.await(received).pipe(
    Effect.timeoutOrElse({
      duration: approvalWindow,
      orElse: () =>
        Effect.fail(new OAuthError({ message: "Sign-in: nobody approved it within five minutes" })),
    }),
  );

  if (callback.state !== state)
    return yield* new OAuthError({ message: "Sign-in: the redirect's state does not match" });

  // RFC 9207: the code must come from the issuer this sign-in asked.
  if (callback.iss !== null && callback.iss !== server.issuer)
    return yield* new OAuthError({ message: `Sign-in: the redirect came from ${callback.iss}` });

  if (callback.code === null)
    return yield* new OAuthError({
      message: `Sign-in: ${callback.error ?? "no code"}${callback.errorDescription ? `: ${callback.errorDescription}` : ""}`,
    });

  const tokens = yield* token(
    "Sign-in",
    server.token_endpoint,
    new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code: callback.code,
      code_verifier: verifier,
      redirect_uri: redirectUri,
      resource,
    }),
  );

  const signIn: SignIn = {
    resource,
    scope: tokens.scope ?? scope,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt: expiry(tokens),
  };

  // Another issuer's sign-ins are dropped: the file keeps one issuer.
  yield* saveSignIn(
    Option.getOrElse(previous, () => ({
      url: origin,
      tokenEndpoint: server.token_endpoint,
      revocationEndpoint: server.revocation_endpoint ?? null,
      clientId,
      signIns: [],
    })),
    signIn,
  );

  return { url: origin, resource, scope: signIn.scope };
}, Effect.scoped);

/**
 * A current access token for `resource`, refreshed first when it has expired or is about
 * to: the refresh token rotates, so the new pair is saved before the token is used.
 */
export const accessToken = Effect.fn("Cli.accessToken")(function* (
  credentials: Credentials,
  resource: string,
) {
  const signIn = credentials.signIns.find((held) => held.resource === resource);

  if (signIn === undefined)
    return yield* new OAuthError({
      message:
        resource === administrationOf(credentials.url)
          ? `Not signed in to administration: run \`clankerauth login ${credentials.url}\` first.`
          : `Not signed in to ${resource}: run \`clankerauth login ${credentials.url} --resource ${resource} --scope "<scopes>"\` first.`,
    });

  if (Date.parse(signIn.expiresAt) - Date.now() > 60_000) return signIn.accessToken;

  const tokens = yield* token(
    "Refresh",
    credentials.tokenEndpoint,
    new URLSearchParams({
      grant_type: "refresh_token",
      client_id: credentials.clientId,
      refresh_token: signIn.refreshToken,
      resource,
    }),
  ).pipe(
    Effect.mapError(
      (error) =>
        new OAuthError({
          message: `${error.message}. Run \`${loginAgain(credentials.url, signIn)}\` again.`,
        }),
    ),
  );

  const refreshed: SignIn = {
    ...signIn,
    scope: tokens.scope ?? signIn.scope,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt: expiry(tokens),
  };

  yield* saveSignIn(credentials, refreshed);

  return refreshed.accessToken;
});

/**
 * Forget the sign-in to `resource`, or every sign-in when none is named, revoking each
 * refresh token first when the issuer can be reached. The file goes with the last one.
 */
export const logout = Effect.fn("Cli.logout")(function* (resource: Option.Option<string>) {
  const stored = yield* readCredentials();

  if (Option.isNone(stored)) return { signedOut: false };

  const credentials = stored.value;

  const leaving = credentials.signIns.filter((signIn) =>
    Option.match(resource, { onNone: () => true, onSome: (named) => signIn.resource === named }),
  );

  const staying = credentials.signIns.filter((signIn) => !leaving.includes(signIn));
  const { revocationEndpoint, clientId } = credentials;

  if (revocationEndpoint !== null)
    yield* Effect.forEach(
      leaving,
      ({ refreshToken }) => Effect.ignore(revoke(revocationEndpoint, clientId, refreshToken)),
      { concurrency: "unbounded", discard: true },
    );

  yield* staying.length === 0
    ? removeCredentials()
    : writeCredentials({ ...credentials, signIns: staying });

  return { signedOut: leaving.length > 0 };
});
