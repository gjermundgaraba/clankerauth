import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { Http, errors } from "@clankerauth/admin-api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { createAuthClient } from "better-auth/client";
import { Array, Effect, Option, Schema, pipe } from "effect";

// ISSUER

/** The issuer's administration actions, each an Effect a Command runs. */
export const issuer = ActionHttp.fetchClient(Http);

/** The issuer's own errors, which every action declares: their sentence is `error`. */
const isIssuerError = Schema.is(Schema.Union(errors));

/** effect-actions' own errors, which every endpoint declares: their sentence is `message`. */
const isBuiltIn = Schema.is(Action.BuiltIn);

const UNKNOWN_FAILURE = "Request could not be completed. Please try again.";

/**
 * The sentence the owner reads for a refused call. The contract's own refusals, and input the
 * issuer cannot serve, carry the sentence written for the owner; input that does not decode
 * carries each rule's sentence as an issue. Anything else reached the browser instead of the
 * issuer's answer, and reads the same either way.
 */
const reasonOf = <E>(error: E): string => {
  if (isIssuerError(error)) {
    return error.error;
  }

  if (error instanceof Action.InvalidInput) {
    return pipe(
      error.issues,
      Array.map(({ message }) => message),
      Array.dedupe,
      Array.match({ onEmpty: () => error.message, onNonEmpty: Array.join(" ") }),
    );
  }

  if (isBuiltIn(error)) {
    return error.message;
  }

  return UNKNOWN_FAILURE;
};

/** An issuer call whose failure, typed or not, is the owner's sentence. */
export const toOwnerSentence = <A, E>(call: Effect.Effect<A, E>): Effect.Effect<A, string> =>
  call.pipe(
    Effect.mapError(reasonOf),
    Effect.catchDefect(() => Effect.fail(UNKNOWN_FAILURE)),
  );

// SESSION

// The provider client follows the OAuth redirects itself: after a sign-in that continues an
// authorization, and after a consent decision.
const auth = createAuthClient({ plugins: [oauthProviderClient()] });

/** Better Auth answers `{ data, error }` rather than rejecting; a rejection is the network. */
const settled = <A, E>(
  call: () => Promise<Readonly<{ data: A | null; error: E | null }>>,
  failure: string,
): Effect.Effect<A, string> =>
  Effect.tryPromise({ try: call, catch: () => failure }).pipe(
    Effect.flatMap(({ data, error }) =>
      error === null && data !== null ? Effect.succeed(data) : Effect.fail(failure),
    ),
  );

/** Whether this browser holds the owner's session. No session is an answer; an error is not. */
export const isSignedIn: Effect.Effect<boolean, string> = Effect.tryPromise({
  try: () => auth.getSession(),
  catch: () => UNKNOWN_FAILURE,
}).pipe(
  Effect.flatMap(({ data, error }) =>
    error === null ? Effect.succeed(data !== null) : Effect.fail(UNKNOWN_FAILURE),
  ),
);

export const signIn = (email: string, password: string): Effect.Effect<void, string> =>
  settled(
    () => auth.signIn.email({ email, password }),
    "Sign-in failed. Check your credentials or try again later.",
  ).pipe(Effect.asVoid);

export const signOut: Effect.Effect<void, string> = settled(
  () => auth.signOut(),
  "Sign-out failed. Please try again.",
).pipe(Effect.asVoid);

/** The display name a client registered, which it chose itself. */
export const publicClientName = (clientId: string): Effect.Effect<Option.Option<string>, string> =>
  settled(
    () => auth.oauth2.publicClient({ query: { client_id: clientId } }),
    "Sign in through your application to continue authorization.",
  ).pipe(Effect.map(({ client_name }) => Option.fromNullishOr(client_name)));

/** Answers the authorization request on this page. On success the provider client follows the
 *  redirect to the client's callback; a second navigation would cancel it. */
export const decideConsent = (
  accept: boolean,
  maybeScope: Option.Option<string>,
): Effect.Effect<void, string> =>
  settled(
    () =>
      auth.oauth2.consent(
        Option.match(maybeScope, {
          onNone: () => ({ accept }),
          onSome: (scope) => ({ accept, scope }),
        }),
      ),
    "Authorization could not be completed. Restart from your application.",
  ).pipe(Effect.asVoid);
