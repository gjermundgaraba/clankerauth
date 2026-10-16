import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { Http, errors } from "@gjermundgaraba/clankerauth-admin-api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { createAuthClient } from "better-auth/client";
import { Array, Effect, Option, Schema, pipe } from "effect";

// ISSUER

export const issuer = ActionHttp.fetchClient(Http);

const isIssuerError = Schema.is(Schema.Union(errors));

const isBuiltIn = Schema.is(Action.BuiltIn);

const UNKNOWN_FAILURE = "Request could not be completed. Please try again.";

const reasonOf = <E>(error: E): string => {
  if (isIssuerError(error)) {
    return error.message;
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

export const toOwnerSentence = <A, E>(call: Effect.Effect<A, E>): Effect.Effect<A, string> =>
  call.pipe(
    Effect.mapError(reasonOf),
    Effect.catchDefect(() => Effect.fail(UNKNOWN_FAILURE)),
  );

// SESSION

// why: the provider client follows OAuth redirects itself; a second navigation would cancel it
const auth = createAuthClient({ plugins: [oauthProviderClient()] });

const settled = <A, E>(
  call: () => Promise<Readonly<{ data: A | null; error: E | null }>>,
  failure: string,
): Effect.Effect<A, string> =>
  Effect.tryPromise({ try: call, catch: () => failure }).pipe(
    Effect.flatMap(({ data, error }) =>
      error === null && data !== null ? Effect.succeed(data) : Effect.fail(failure),
    ),
  );

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

export const publicClientName = (clientId: string): Effect.Effect<Option.Option<string>, string> =>
  settled(
    () => auth.oauth2.publicClient({ query: { client_id: clientId } }),
    "Sign in through your application to continue authorization.",
  ).pipe(Effect.map(({ client_name }) => Option.fromNullishOr(client_name)));

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
