import { serializeSignedCookie } from "better-call";
import { Effect } from "effect";
import { apiError } from "./api-errors.ts";
import type { Service } from "./auth.ts";

/** The pinned provider's administration APIs require a signed session cookie.
 * Keep the adapter session inside the authenticated request scope and never
 * forward this cookie to the MCP client. Its short expiry bounds crash residue.
 */
export const providerSession = Effect.fn("Mcp.providerSession")(function* (
  service: Service,
  userId: string,
  tokenExpiresAt: number,
) {
  // Registered first, released last: shutdown waits for session deletion even
  // when native HTTP handling has already returned its Response to the caller.
  yield* Effect.acquireRelease(Effect.try({ try: service.retain, catch: apiError }), (release) =>
    Effect.sync(release),
  );
  const context = yield* Effect.tryPromise({ try: () => service.auth.$context, catch: apiError });

  const session = yield* Effect.acquireRelease(
    Effect.tryPromise({
      try: () =>
        context.internalAdapter.createSession(
          userId,
          true,
          {
            expiresAt: new Date(Math.min(tokenExpiresAt * 1000, Date.now() + 60_000)),
          },
          true,
        ),
      catch: apiError,
    }),
    (session) => Effect.promise(() => context.internalAdapter.deleteSession(session.token)),
  );

  const cookie = yield* Effect.tryPromise({
    try: async () =>
      (
        await Promise.all([
          serializeSignedCookie(
            context.authCookies.sessionToken.name,
            session.token,
            context.secret,
          ),
          // Prevent getSession from extending this request-local session's expiry.
          serializeSignedCookie(context.authCookies.dontRememberToken.name, "true", context.secret),
        ])
      )
        .map((cookie) => cookie.split(";")[0])
        .join("; "),
    catch: apiError,
  });

  return new Headers({ origin: service.settings.baseURL, cookie });
});
