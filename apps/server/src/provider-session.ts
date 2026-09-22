import { serializeSignedCookie } from "better-call";
import { Clock, Effect } from "effect";
import { provider } from "./api-errors.ts";
import type { Auth } from "./auth.ts";

/** The pinned provider's administration APIs require a signed session cookie.
 * The session lives in the calling scope, which deletes it on close; never put this
 * cookie in a response. Its one-minute expiry bounds crash residue.
 */
export const providerSession = Effect.fn("Administration.providerSession")(function* (
  service: Auth["Service"],
  userId: string,
) {
  const { context } = service;
  const expiresAt = new Date((yield* Clock.currentTimeMillis) + 60_000);

  const session = yield* Effect.acquireRelease(
    provider(() => context.internalAdapter.createSession(userId, true, { expiresAt }, true)),
    (session) => Effect.promise(() => context.internalAdapter.deleteSession(session.token)),
  );

  const cookie = yield* provider(async () =>
    (
      await Promise.all([
        serializeSignedCookie(context.authCookies.sessionToken.name, session.token, context.secret),
        // Prevent getSession from extending this request-local session's expiry.
        serializeSignedCookie(context.authCookies.dontRememberToken.name, "true", context.secret),
      ])
    )
      .map((cookie) => cookie.split(";")[0])
      .join("; "),
  );

  return new Headers({ origin: service.settings.baseURL, cookie });
});
