import { serializeSignedCookie } from "better-call";
import { Clock, Effect } from "effect";
import { provider } from "./api-errors.ts";
import type { Auth } from "./auth.ts";

/** The pinned provider's administration APIs require a signed session cookie.
 * Keep the adapter session inside the authenticated request scope and never
 * forward this cookie to the caller. Its one-minute expiry bounds crash residue.
 */
export const providerSession = Effect.fn("Administration.providerSession")(function* (
  service: Auth["Service"],
  userId: string,
) {
  const context = yield* provider(() => service.auth.$context);
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
