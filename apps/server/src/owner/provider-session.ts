import { Clock, Effect, Redacted } from "effect";

import { signedSessionCookie } from "../issuer/cookies.ts";
import { provider } from "../issuer/errors.ts";
import type { ProviderContext } from "../issuer/issuer.ts";

/** A one-minute session administration acts through, deleted when its scope closes. */
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

/** An owner session, as its `Cookie` header, minted without the rate-limited sign-in. */
export const ownerSessionFor = (context: ProviderContext) =>
  Effect.fn("OwnerAccount.session")(function* (userId: string) {
    const { token } = yield* provider(
      async () => await context.internalAdapter.createSession(userId)
    );

    return Redacted.make(
      yield* provider(async () => await signedSessionCookie(context, token))
    );
  }, Effect.uninterruptible);
