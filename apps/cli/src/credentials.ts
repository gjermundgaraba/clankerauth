import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { Effect, Option, Schema } from "effect";

/** The kept sign-ins cannot be read or written. */
export class CredentialsError extends Schema.TaggedError<CredentialsError>()("CredentialsError", {
  message: Schema.String,
}) {}

const failed = (what: string) => (error: { readonly message: string }) =>
  new CredentialsError({ message: `${what} ${credentialsPath()}: ${error.message}` });

/**
 * The owner's authorization for one resource: administration or an application's. The
 * access token lasts fifteen minutes and the refresh token rotates on every use, so the
 * file is rewritten whenever a command refreshes.
 */
export const SignIn = Schema.Struct({
  /** The token audience: a resource identifier, such as `https://notes.home.example/`. */
  resource: Schema.String,
  scope: Schema.String,
  accessToken: Schema.String,
  refreshToken: Schema.String,
  /** When the access token expires, as an ISO instant. */
  expiresAt: Schema.String,
});

export type SignIn = typeof SignIn.Type;

/**
 * The issuer signed in to, the client this CLI registered there, and one sign-in per
 * resource. `server` is the part of the issuer's RFC 8414 metadata a refresh and a
 * revocation need, under its RFC names.
 */
export const Credentials = Schema.Struct({
  /** The issuer's origin, `CLANKERAUTH_BASE_URL`: where `/api/owner/<action>` is served. */
  url: Schema.String,
  server: Schema.Struct({
    issuer: Schema.String,
    token_endpoint: Schema.String,
    revocation_endpoint: Schema.String,
  }),
  clientId: Schema.String,
  signIns: Schema.Array(SignIn),
});

export type Credentials = typeof Credentials.Type;

const CredentialsJson = Schema.fromJsonString(Credentials);

export const credentialsPath = () =>
  join(
    process.env["XDG_CONFIG_HOME"] || join(homedir(), ".config"),
    "clankerauth",
    "credentials.json",
  );

export const readCredentials = () =>
  Effect.tryPromise(() => readFile(credentialsPath(), "utf8")).pipe(
    Effect.map(Schema.decodeOption(CredentialsJson)),
    Effect.catchIf(
      (error) =>
        error.cause instanceof Error && "code" in error.cause && error.cause.code === "ENOENT",
      () => Effect.succeedNone,
    ),
    Effect.mapError(failed("Cannot read")),
  );

export const writeCredentials = Effect.fn("Credentials.write")(
  function* (credentials: Credentials) {
    const path = credentialsPath();
    const json = yield* Schema.encodeEffect(CredentialsJson)(credentials);
    // why: staged and renamed, so an interrupted write never leaves a refresh token half-saved.
    const staging = `${path}.${randomBytes(6).toString("hex")}`;

    yield* Effect.tryPromise(async () => {
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(staging, `${json}\n`, { mode: 0o600 });
      await rename(staging, path);
    }).pipe(Effect.tapError(() => Effect.promise(() => rm(staging, { force: true }))));
  },
  Effect.mapError(failed("Cannot write")),
);

export const saveSignIn = Effect.fn("Credentials.saveSignIn")(function* (
  issuer: Credentials,
  signIn: SignIn,
) {
  // why: re-read, so a concurrent refresh of another resource keeps its rotated refresh token.
  const current = Option.filter(yield* readCredentials(), ({ url }) => url === issuer.url);
  const base = Option.getOrElse(current, () => issuer);

  yield* writeCredentials({
    ...base,
    signIns: [...base.signIns.filter(({ resource }) => resource !== signIn.resource), signIn],
  });
});

export const removeCredentials = () =>
  Effect.tryPromise(() => rm(credentialsPath(), { force: true })).pipe(
    Effect.mapError(failed("Cannot remove")),
  );
