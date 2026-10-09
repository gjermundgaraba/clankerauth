import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { Effect, Option, Schema, SchemaGetter } from "effect";

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

const issuerFields = {
  /** The issuer's origin, `CLANKERAUTH_BASE_URL`: where `/api/owner/<action>` is served. */
  url: Schema.String,
  tokenEndpoint: Schema.String,
  /** Where `logout` revokes a refresh token; null when the issuer publishes none. */
  revocationEndpoint: Schema.NullOr(Schema.String),
  clientId: Schema.String,
};

/** The issuer signed in to, the client this CLI registered there, and one sign-in per resource. */
export const Credentials = Schema.Struct({ ...issuerFields, signIns: Schema.Array(SignIn) });

export type Credentials = typeof Credentials.Type;

/** What 0.16.0 kept: one sign-in, to administration, beside the issuer's fields. */
const Before017 = Schema.Struct({ ...issuerFields, ...SignIn.fields });

const CredentialsJson = Schema.fromJsonString(Credentials);

/** A file either version wrote, as this version keeps it. */
const StoredJson = Schema.fromJsonString(
  Schema.Union([
    Credentials,
    Before017.pipe(
      Schema.decodeTo(Credentials, {
        decode: SchemaGetter.transform(
          ({ resource, scope, accessToken, refreshToken, expiresAt, ...issuer }) => ({
            ...issuer,
            signIns: [{ resource, scope, accessToken, refreshToken, expiresAt }],
          }),
        ),
        // Only this version's form is ever written.
        encode: SchemaGetter.forbiddenEncoding,
      }),
    ),
  ]),
);

/** Where the sign-ins are kept: `$XDG_CONFIG_HOME/clankerauth`, or `~/.config/clankerauth`. */
export const credentialsPath = () =>
  join(
    process.env["XDG_CONFIG_HOME"] || join(homedir(), ".config"),
    "clankerauth",
    "credentials.json",
  );

/** The sign-ins, if there are any. A file that does not decode is a failure, not a sign-out. */
export const readCredentials = Effect.fn("Credentials.read")(
  function* () {
    const text = yield* Effect.tryPromise(() => readFile(credentialsPath(), "utf8")).pipe(
      Effect.map(Option.some),
      Effect.catchIf(
        (error) =>
          error.cause instanceof Error && "code" in error.cause && error.cause.code === "ENOENT",
        () => Effect.succeed(Option.none<string>()),
      ),
    );

    return yield* Option.match(text, {
      onNone: () => Effect.succeedNone,
      onSome: (json) => Effect.map(Schema.decodeEffect(StoredJson)(json), Option.some),
    });
  },
  Effect.mapError(failed("Cannot read")),
);

/**
 * Replace the sign-ins, readable by their owner alone. Written beside the file and renamed
 * over it, so a command interrupted mid-write never leaves a refresh token half-saved.
 */
export const writeCredentials = Effect.fn("Credentials.write")(
  function* (credentials: Credentials) {
    const path = credentialsPath();
    const json = yield* Schema.encodeEffect(CredentialsJson)(credentials);
    const staging = `${path}.${randomBytes(6).toString("hex")}`;

    yield* Effect.tryPromise(async () => {
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(staging, `${json}\n`, { mode: 0o600 });
      await rename(staging, path);
    }).pipe(Effect.tapError(() => Effect.promise(() => rm(staging, { force: true }))));
  },
  Effect.mapError(failed("Cannot write")),
);

/**
 * Keep `signIn` in place of the one for its resource. The file is read again first, so a
 * command refreshing another resource meanwhile keeps its rotated refresh token too.
 */
export const saveSignIn = Effect.fn("Credentials.saveSignIn")(function* (
  issuer: Credentials,
  signIn: SignIn,
) {
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
