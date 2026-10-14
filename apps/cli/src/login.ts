import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Deferred, Effect, Option } from "effect";
import { administrationIdentifier, administrationScopes } from "@clankerauth/admin-api";
import {
  readCredentials,
  removeCredentials,
  saveSignIn,
  writeCredentials,
  type Credentials,
  type SignIn,
} from "./credentials.ts";
import {
  authorizationRequest,
  discover,
  exchangeCode,
  OAuthError,
  refresh,
  register,
  revoke,
  type Tokens,
} from "./oauth.ts";

export const administrationScope = `${administrationScopes.read} ${administrationScopes.write}`;

const withRefresh = (scope: string) =>
  scope.split(" ").includes("offline_access") ? scope : `${scope} offline_access`;

export const loginHint = (url: string, resource: string, scope?: string) => {
  const asked = scope
    ?.split(" ")
    .filter((granted) => granted !== "offline_access")
    .join(" ");

  const administration = resource === administrationIdentifier(url);
  const resourceFlag = administration ? "" : ` --resource ${resource}`;

  const scopeFlag =
    administration && (asked === undefined || asked === administrationScope)
      ? ""
      : ` --scope "${asked ?? "<scopes>"}"`;

  return `clankerauth login ${url}${resourceFlag}${scopeFlag}`;
};

// why: loopback redirects match without their port (RFC 8252), so one registration serves all.
const registeredRedirect = "http://127.0.0.1/callback";

const approvalWindow = "5 minutes";

const expiry = (tokens: Tokens) =>
  new Date(Date.now() + (tokens.expires_in ?? 0) * 1000).toISOString();

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

    const port = yield* Effect.callback<number, OAuthError>((resume) => {
      server.once("error", (error) =>
        resume(
          Effect.fail(
            new OAuthError({ message: `Cannot listen for the redirect: ${error.message}` }),
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

const revokeAll = (credentials: Credentials, signIns: ReadonlyArray<SignIn>) =>
  Effect.forEach(signIns, ({ refreshToken }) => Effect.ignore(revoke(credentials, refreshToken)), {
    concurrency: "unbounded",
    discard: true,
  });

export const login = Effect.fn("Cli.login")(function* (
  url: string,
  target: Option.Option<string>,
  asked: string,
) {
  const origin = new URL(url).origin;
  const server = yield* discover(origin);
  const resource = Option.getOrElse(target, () => administrationIdentifier(origin));
  const kept = yield* readCredentials();
  const previous = Option.filter(kept, (credentials) => credentials.url === origin);

  const clientId = yield* Option.match(previous, {
    onSome: (credentials) => Effect.succeed(credentials.clientId),
    onNone: () => register(origin, server, registeredRedirect),
  });

  const { port, received } = yield* listen;
  const redirectUri = `http://127.0.0.1:${port}/callback`;
  const scope = withRefresh(asked);

  const {
    url: authorization,
    state,
    verifier,
  } = yield* authorizationRequest(server, clientId, redirectUri, scope, resource);

  yield* Effect.sync(() =>
    process.stderr.write(
      `Open this URL in your browser to approve the sign-in:\n\n  ${authorization.href}\n\n`,
    ),
  );

  const callback = yield* Deferred.await(received).pipe(
    Effect.timeoutOrElse({
      duration: approvalWindow,
      orElse: () =>
        Effect.fail(new OAuthError({ message: "Sign-in: nobody approved it within five minutes" })),
    }),
  );

  const tokens = yield* exchangeCode(
    origin,
    server,
    clientId,
    callback,
    { state, verifier, redirectUri },
    resource,
  );

  if (tokens.refresh_token === undefined)
    return yield* new OAuthError({ message: "Sign-in: the issuer issued no refresh token" });

  const signIn: SignIn = {
    resource,
    scope: tokens.scope ?? scope,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt: expiry(tokens),
  };

  if (Option.isSome(kept) && Option.isNone(previous)) {
    yield* revokeAll(kept.value, kept.value.signIns);
    yield* removeCredentials();
  }

  yield* saveSignIn(
    Option.getOrElse(previous, () => ({
      url: origin,
      server: {
        issuer: server.issuer,
        token_endpoint: server.token_endpoint,
        revocation_endpoint: server.revocation_endpoint,
      },
      clientId,
      signIns: [],
    })),
    signIn,
  );

  return { url: origin, resource, scope: signIn.scope };
}, Effect.scoped);

export const accessToken = Effect.fn("Cli.accessToken")(function* (
  credentials: Credentials,
  resource: string,
) {
  const signIn = credentials.signIns.find((held) => held.resource === resource);

  if (signIn === undefined)
    return yield* new OAuthError({
      message: `Not signed in to ${resource}: run \`${loginHint(credentials.url, resource)}\` first.`,
    });

  if (Date.parse(signIn.expiresAt) - Date.now() > 60_000) return signIn.accessToken;

  const tokens = yield* refresh(credentials, signIn.refreshToken, resource).pipe(
    Effect.mapError(
      (error) =>
        new OAuthError({
          message: `${error.message}. Run \`${loginHint(credentials.url, resource, signIn.scope)}\` again.`,
        }),
    ),
  );

  const refreshed: SignIn = {
    ...signIn,
    scope: tokens.scope ?? signIn.scope,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token ?? signIn.refreshToken,
    expiresAt: expiry(tokens),
  };

  yield* saveSignIn(credentials, refreshed);

  return refreshed.accessToken;
});

export const logout = Effect.fn("Cli.logout")(function* (resource: Option.Option<string>) {
  const stored = yield* readCredentials();

  if (Option.isNone(stored)) {
    yield* removeCredentials();

    return { signedOut: false };
  }

  const credentials = stored.value;

  const leaving = credentials.signIns.filter((signIn) =>
    Option.match(resource, { onNone: () => true, onSome: (named) => signIn.resource === named }),
  );

  const staying = credentials.signIns.filter((signIn) => !leaving.includes(signIn));

  yield* revokeAll(credentials, leaving);
  yield* staying.length === 0
    ? removeCredentials()
    : writeCredentials({ ...credentials, signIns: staying });

  return { signedOut: leaving.length > 0 };
});
