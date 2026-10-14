import { Clock, Effect } from "effect";
import { internal, provider } from "../issuer/errors.ts";
import { signedSessionCookie } from "../issuer/cookies.ts";
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

    const cookie = yield* internal(provider(() => signedSessionCookie(context, session.token)));

    return new Headers({ origin, cookie });
  });
