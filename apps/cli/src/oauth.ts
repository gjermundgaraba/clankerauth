import * as oauth from "oauth4webapi";
import { Effect, Option, Schema } from "effect";
import type { Credentials } from "./credentials.ts";

export class OAuthError extends Schema.TaggedError<OAuthError>()("OAuthError", {
  message: Schema.String,
}) {}

const Server = Schema.Struct({
  issuer: Schema.String,
  authorization_endpoint: Schema.String,
  token_endpoint: Schema.String,
  registration_endpoint: Schema.String,
  revocation_endpoint: Schema.String,
});

export type Server = typeof Server.Type;

export const client = (clientId: string): oauth.Client => ({ client_id: clientId });

// why: plain HTTP only for an issuer the owner named with `http:`, such as one on loopback.
const transport = (url: string) => ({
  [oauth.allowInsecureRequests]: new URL(url).protocol === "http:",
});

const NamedElsewhere = Schema.Struct({
  attribute: Schema.Literal("resource"),
  body: Schema.Struct({ resource: Schema.String }),
});

const reason = (error: Error) => {
  if (error instanceof oauth.ResponseBodyError || error instanceof oauth.AuthorizationResponseError)
    return [error.error, error.error_description].filter(Boolean).join(": ");

  if (error instanceof oauth.OperationProcessingError) {
    const named = Schema.decodeUnknownOption(NamedElsewhere)(error.cause);

    if (Option.isSome(named))
      return `the issuer is at ${new URL(named.value.body.resource).origin}, its CLANKERAUTH_BASE_URL: sign in there`;

    if (error.cause instanceof Response) return `${error.message} (HTTP ${error.cause.status})`;
  }

  return error.cause instanceof Error ? `${error.message} (${error.cause.message})` : error.message;
};

const step = <A>(what: string, run: () => Promise<A>) =>
  Effect.tryPromise({
    try: run,
    catch: (error) =>
      new OAuthError({
        message: `${what}: ${error instanceof Error ? reason(error) : String(error)}`,
      }),
  });

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

/** What an issuer answers a token request with. */
export type Tokens = oauth.TokenEndpointResponse;

export const authorizationRequest = Effect.fn("OAuth.authorizationRequest")(function* (
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
