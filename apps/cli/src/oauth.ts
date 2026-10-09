import * as oauth from "oauth4webapi";
import { Effect, Option, Schema } from "effect";
import type { Credentials } from "./credentials.ts";

/** Something the issuer answered that a sign-in, a refresh or a revocation cannot go on from. */
export class OAuthError extends Schema.TaggedError<OAuthError>()("OAuthError", {
  message: Schema.String,
}) {}

/** The issuer's RFC 8414 metadata a sign-in uses, every endpoint required. */
const Server = Schema.Struct({
  issuer: Schema.String,
  authorization_endpoint: Schema.String,
  token_endpoint: Schema.String,
  registration_endpoint: Schema.String,
  revocation_endpoint: Schema.String,
});

export type Server = typeof Server.Type;

/** This CLI as the issuer knows it: a public client, authenticating with nothing. */
export const client = (clientId: string): oauth.Client => ({ client_id: clientId });

/** Plain HTTP is allowed for an issuer the owner named over it, such as one on loopback. */
const transport = (url: string) => ({
  [oauth.allowInsecureRequests]: new URL(url).protocol === "http:",
});

/** The RFC 9728 check's failure: the metadata names another resource than the one asked for. */
const NamedElsewhere = Schema.Struct({
  attribute: Schema.Literal("resource"),
  body: Schema.Struct({ resource: Schema.String }),
});

/**
 * What went wrong: what the issuer said when it sent an OAuth error, where it is when it
 * names another address than the one asked, the status of an answer the library refused,
 * or why a request failed.
 */
const reason = (error: Error) => {
  if (error instanceof oauth.ResponseBodyError || error instanceof oauth.AuthorizationResponseError)
    return [error.error, error.error_description].filter(Boolean).join(": ");

  if (error instanceof oauth.OperationProcessingError) {
    const named = Schema.decodeUnknownOption(NamedElsewhere)(error.cause);

    if (Option.isSome(named))
      return `the issuer is at ${new URL(named.value.body.resource).origin}, its CLANKERAUTH_BASE_URL: sign in there`;

    if (error.cause instanceof Response) return `${error.message} (HTTP ${error.cause.status})`;
  }

  // `fetch` says only "fetch failed"; its cause says why, such as ECONNREFUSED.
  return error.cause instanceof Error ? `${error.message} (${error.cause.message})` : error.message;
};

/** Run one step of the protocol, failing with what the issuer, or the library, said. */
const step = <A>(what: string, run: () => Promise<A>) =>
  Effect.tryPromise({
    try: run,
    catch: (error) =>
      new OAuthError({
        message: `${what}: ${error instanceof Error ? reason(error) : String(error)}`,
      }),
  });

/**
 * The issuer at `url`, its origin: administration's RFC 9728 metadata at the origin root,
 * which must name that root, and the RFC 8414 metadata of the issuer it names, which must
 * name that issuer. Both checks are the library's.
 */
export const discover = Effect.fn("OAuth.discover")(function* (url: string) {
  const administration = new URL("/", url);

  const metadata = yield* step(`Discovery at ${administration.origin}`, async () =>
    oauth.processResourceDiscoveryResponse(
      administration,
      await oauth.resourceDiscoveryRequest(administration, transport(url)),
    ),
  );

  const [named] = metadata.authorization_servers ?? [];

  if (named === undefined)
    return yield* new OAuthError({
      message: "Discovery: the issuer names no authorization server",
    });

  const issuer = new URL(named);

  const server = yield* step("Discovery", async () =>
    oauth.processDiscoveryResponse(
      issuer,
      await oauth.discoveryRequest(issuer, { algorithm: "oauth2", ...transport(url) }),
    ),
  );

  return yield* Schema.decodeUnknownEffect(Server)(server).pipe(
    Effect.mapError(
      (error) =>
        new OAuthError({ message: `Discovery: the issuer lacks an endpoint (${error.message})` }),
    ),
  );
});

/**
 * Register this CLI as a public native client. The issuer matches a loopback redirect without
 * its port (RFC 8252), so one registration serves every port a sign-in listens on.
 */
export const register = (url: string, server: Server, redirectUri: string) =>
  step("Registration", async () =>
    oauth.processDynamicClientRegistrationResponse(
      await oauth.dynamicClientRegistrationRequest(
        server,
        {
          client_name: "clankerauth CLI",
          redirect_uris: [redirectUri],
          application_type: "native",
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
        },
        transport(url),
      ),
    ),
  ).pipe(Effect.map((registered) => registered.client_id));

/**
 * Check the redirect a browser brought back (its state, the RFC 9207 issuer, an error the
 * issuer sent instead of a code) and exchange its code for tokens.
 */
export const exchangeCode = (
  url: string,
  server: Server,
  clientId: string,
  callback: URLSearchParams,
  expected: { readonly state: string; readonly verifier: string; readonly redirectUri: string },
  resource: string,
) =>
  step("Sign-in", async () => {
    const parameters = oauth.validateAuthResponse(
      server,
      client(clientId),
      callback,
      expected.state,
    );

    return oauth.processAuthorizationCodeResponse(
      server,
      client(clientId),
      await oauth.authorizationCodeGrantRequest(
        server,
        client(clientId),
        oauth.None(),
        parameters,
        expected.redirectUri,
        expected.verifier,
        { additionalParameters: { resource }, ...transport(url) },
      ),
    );
  });

/** Refresh the tokens of one sign-in: the refresh token rotates. */
export const refresh = (credentials: Credentials, refreshToken: string, resource: string) =>
  step("Refresh", async () =>
    oauth.processRefreshTokenResponse(
      credentials.server,
      client(credentials.clientId),
      await oauth.refreshTokenGrantRequest(
        credentials.server,
        client(credentials.clientId),
        oauth.None(),
        refreshToken,
        { additionalParameters: { resource }, ...transport(credentials.url) },
      ),
    ),
  );

/** Revoke a refresh token, and with it every token of its family. */
export const revoke = (credentials: Credentials, refreshToken: string) =>
  step("Revocation", async () =>
    oauth.processRevocationResponse(
      await oauth.revocationRequest(
        credentials.server,
        client(credentials.clientId),
        oauth.None(),
        refreshToken,
        {
          additionalParameters: { token_type_hint: "refresh_token" },
          ...transport(credentials.url),
        },
      ),
    ),
  );
