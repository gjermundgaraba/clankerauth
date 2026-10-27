import { Clock, Effect } from "effect";

import { signedSessionCookie } from "../issuer/cookies.ts";
import { provider } from "../issuer/errors.ts";
import type { ProviderContext } from "../issuer/issuer.ts";

// why: provider admin APIs need a session cookie, which must never reach a response
export const providerSessionFor = (context: ProviderContext, origin: string) =>
  Effect.fn("OwnerAccount.providerSession")(function* (userId: string) {
    const expiresAt = new Date((yield* Clock.currentTimeMillis) + 60_000);

    const session = yield* Effect.acquireRelease(
      provider(
        async () =>
          await context.internalAdapter.createSession(
            userId,
            true,
            { expiresAt },
            true
          )
      ),
      ({ token }) =>
        Effect.promise(async () => {
          await context.internalAdapter.deleteSession(token);
        })
    );

    const cookie = yield* provider(
      async () => await signedSessionCookie(context, session.token)
    );

    return new Headers({ origin, cookie });
  });
