import { Effect, Option, Schema } from "effect";

/** Something the issuer answered that a sign-in or a refresh cannot go on from. */
export class OAuthError extends Schema.TaggedError<OAuthError>()("OAuthError", {
  message: Schema.String,
}) {}

/** RFC 9728: where a resource says its tokens come from. */
const ProtectedResource = Schema.Struct({
  resource: Schema.String,
  authorization_servers: Schema.NonEmptyArray(Schema.String),
});

/** RFC 8414: the endpoints a sign-in uses. */
const AuthorizationServer = Schema.Struct({
  issuer: Schema.String,
  authorization_endpoint: Schema.String,
  token_endpoint: Schema.String,
  registration_endpoint: Schema.String,
  revocation_endpoint: Schema.optionalKey(Schema.String),
});

export type AuthorizationServer = typeof AuthorizationServer.Type;

const Registration = Schema.Struct({ client_id: Schema.String });

export const Tokens = Schema.Struct({
  access_token: Schema.String,
  refresh_token: Schema.String,
  expires_in: Schema.Number,
  scope: Schema.optionalKey(Schema.String),
});

export type Tokens = typeof Tokens.Type;

/** An OAuth error response's fields, when the issuer sent one. */
const ErrorBody = Schema.Struct({
  error: Schema.String,
  error_description: Schema.optionalKey(Schema.String),
});

/** Send `request` and decode its JSON as `schema`, failing with what the issuer said. */
const exchange = <A, I>(
  what: string,
  schema: Schema.Codec<A, I>,
  request: () => Promise<Response>,
) =>
  Effect.gen(function* () {
    const response = yield* Effect.tryPromise({
      try: request,
      catch: (error) =>
        new OAuthError({ message: `${what}: the issuer cannot be reached (${String(error)})` }),
    });

    const text = yield* Effect.promise(() => response.text());

    if (!response.ok) {
      const reason = Option.match(
        Schema.decodeUnknownOption(Schema.fromJsonString(ErrorBody))(text),
        {
          onNone: () => `HTTP ${response.status}`,
          onSome: (body) =>
            body.error_description === undefined
              ? body.error
              : `${body.error}: ${body.error_description}`,
        },
      );

      return yield* new OAuthError({ message: `${what}: ${reason}` });
    }

    return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(schema))(text).pipe(
      Effect.mapError(
        (error) => new OAuthError({ message: `${what}: unexpected answer (${error.message})` }),
      ),
    );
  });

/**
 * The issuer at `url` as a sign-in reaches it: its administration resource, published at the
 * origin root's RFC 9728 document, and the authorization server that resource names.
 */
export const discover = Effect.fn("OAuth.discover")(function* (url: string) {
  const resource = yield* exchange("Discovery", ProtectedResource, () =>
    fetch(new URL("/.well-known/oauth-protected-resource", url)),
  );

  const issuer = new URL(resource.authorization_servers[0]);

  // RFC 8414 inserts the well-known segment before the issuer's path.
  const metadata = new URL(
    `/.well-known/oauth-authorization-server${issuer.pathname === "/" ? "" : issuer.pathname}`,
    issuer,
  );

  const server = yield* exchange("Discovery", AuthorizationServer, () => fetch(metadata));

  return { resource: resource.resource, server };
});

/**
 * Register this CLI as a public native client. The issuer matches a loopback redirect without
 * its port (RFC 8252), so one registration serves every port a sign-in listens on.
 */
export const register = Effect.fn("OAuth.register")(function* (
  server: AuthorizationServer,
  redirectUri: string,
) {
  const registration = yield* exchange("Registration", Registration, () =>
    fetch(server.registration_endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "clankerauth CLI",
        redirect_uris: [redirectUri],
        application_type: "native",
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    }),
  );

  return registration.client_id;
});

/** Ask the token endpoint for tokens, with the grant's own form fields. */
export const token = (what: string, endpoint: string, form: URLSearchParams) =>
  exchange(what, Tokens, () =>
    fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form,
    }),
  );

/** Revoke a refresh token, and with it every token of its family. */
export const revoke = (endpoint: string, clientId: string, refreshToken: string) =>
  Effect.tryPromise(() =>
    fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: refreshToken,
        token_type_hint: "refresh_token",
        client_id: clientId,
      }),
    }),
  );
