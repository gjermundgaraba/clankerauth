import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { Effect, Option, Schema } from "effect";

/** The kept sign-in cannot be read or written. */
export class CredentialsError extends Schema.TaggedError<CredentialsError>()("CredentialsError", {
  message: Schema.String,
}) {}

const failed = (what: string) => (error: { readonly message: string }) =>
  new CredentialsError({ message: `${what} ${credentialsPath()}: ${error.message}` });

/**
 * One owner sign-in: the issuer it is for, the client it registered as, and its tokens. The
 * access token lasts fifteen minutes and the refresh token rotates on every use, so the file
 * is rewritten whenever a command refreshes.
 */
export const Credentials = Schema.Struct({
  /** The issuer's origin, `CLANKERAUTH_BASE_URL`: where `/api/owner/<action>` is served. */
  url: Schema.String,
  /** The administration resource, the token audience: the issuer's origin root. */
  resource: Schema.String,
  tokenEndpoint: Schema.String,
  /** Where `logout` revokes the refresh token; null when the issuer publishes none. */
  revocationEndpoint: Schema.NullOr(Schema.String),
  clientId: Schema.String,
  scope: Schema.String,
  accessToken: Schema.String,
  refreshToken: Schema.String,
  /** When the access token expires, as an ISO instant. */
  expiresAt: Schema.String,
});

export type Credentials = typeof Credentials.Type;

const CredentialsJson = Schema.fromJsonString(Credentials);

/** Where the sign-in is kept: `$XDG_CONFIG_HOME/clankerauth`, or `~/.config/clankerauth`. */
export const credentialsPath = () =>
  join(
    process.env["XDG_CONFIG_HOME"] || join(homedir(), ".config"),
    "clankerauth",
    "credentials.json",
  );

/** The sign-in, if there is one. A file that does not decode is a failure, not a sign-out. */
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
      onSome: (json) => Effect.map(Schema.decodeEffect(CredentialsJson)(json), Option.some),
    });
  },
  Effect.mapError(failed("Cannot read")),
);

/**
 * Replace the sign-in, readable by its owner alone. Written beside it and renamed over it, so
 * a command interrupted mid-write never leaves a refresh token half-saved.
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

export const removeCredentials = () =>
  Effect.tryPromise(() => rm(credentialsPath(), { force: true })).pipe(
    Effect.mapError(failed("Cannot remove")),
  );
