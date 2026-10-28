import { Clock, Effect, Redacted } from "effect";

import { signedSessionCookie } from "../issuer/cookies.ts";
import { provider } from "../issuer/errors.ts";
import type { ProviderContext } from "../issuer/issuer.ts";

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

    return Redacted.make(new Headers({ origin, cookie }));
  });
