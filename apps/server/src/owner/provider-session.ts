import { serializeSignedCookie } from "better-call";
import { Clock, Effect } from "effect";
import { internal, provider } from "../issuer/errors.ts";
import type { ProviderContext } from "../issuer/issuer.ts";

// why: provider admin APIs need a session cookie, which must never reach a response
export const providerSessionFor = (context: ProviderContext, origin: string) =>
  Effect.fn("Administration.providerSession")(function* (userId: string) {
    const expiresAt = new Date((yield* Clock.currentTimeMillis) + 60_000);

    const session = yield* Effect.acquireRelease(
      internal(
        provider(() => context.internalAdapter.createSession(userId, true, { expiresAt }, true)),
      ),
      (session) => Effect.promise(() => context.internalAdapter.deleteSession(session.token)),
    );

    const cookie = yield* internal(
      provider(async () =>
        (
          await Promise.all([
            serializeSignedCookie(
              context.authCookies.sessionToken.name,
              session.token,
              context.secret,
            ),
            // why: stops getSession from extending this request-local session's expiry
            serializeSignedCookie(
              context.authCookies.dontRememberToken.name,
              "true",
              context.secret,
            ),
          ])
        )
          .map((cookie) => cookie.split(";")[0])
          .join("; "),
      ),
    );

    return new Headers({ origin, cookie });
  });
