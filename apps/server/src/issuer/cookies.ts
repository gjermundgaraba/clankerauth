import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { serializeSignedCookie } from "better-call";
import { Effect } from "effect";

import type { ProviderContext } from "./issuer.ts";

export const seal = (key: string, data: string) =>
  Effect.tryPromise(async () => await symmetricEncrypt({ key, data }));

export const unseal = (key: string, data: string) =>
  Effect.tryPromise(async () => await symmetricDecrypt({ key, data }));

/**
 * The `Cookie` header that presents a session. A session created not to be remembered
 * carries the provider's don't-remember cookie too, so `getSession` never extends it.
 */
export const signedSessionCookie = async (
  context: ProviderContext,
  token: string,
  remembered: boolean
) => {
  const cookies = await Promise.all([
    serializeSignedCookie(
      context.authCookies.sessionToken.name,
      token,
      context.secret
    ),
    ...(remembered
      ? []
      : [
          serializeSignedCookie(
            context.authCookies.dontRememberToken.name,
            "true",
            context.secret
          ),
        ]),
  ]);

  return cookies.map((cookie) => cookie.split(";")[0]).join("; ");
};
