import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { serializeSignedCookie } from "better-call";
import { Effect } from "effect";
import type { ProviderContext } from "./issuer.ts";

export const seal = (key: string, data: string) =>
  Effect.tryPromise(() => symmetricEncrypt({ key, data }));

export const unseal = (key: string, data: string) =>
  Effect.tryPromise(() => symmetricDecrypt({ key, data }));

export const signedSessionCookie = async (context: ProviderContext, token: string) =>
  (
    await Promise.all([
      serializeSignedCookie(context.authCookies.sessionToken.name, token, context.secret),
      // why: stops getSession from extending this request-local session's expiry
      serializeSignedCookie(context.authCookies.dontRememberToken.name, "true", context.secret),
    ])
  )
    .map((cookie) => cookie.split(";")[0])
    .join("; ");
