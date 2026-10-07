import { Effect, Schema } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { FetchHttpClient } from "effect/http";
import { SignJWT } from "jose";
import * as KeyList from "../src/key-list.ts";
import { Resource } from "../src/effect-actions.ts";
import { CurrentPrincipal } from "../src/session.ts";
import { ProviderUnavailable } from "../src/errors.ts";
import { startFakeIssuer } from "../src/testing.ts";

export const publicUrl = "http://127.0.0.1:7337";

/** A refusal as every effect-actions surface sends it. */
export const sent = Schema.encodeSync(Schema.toCodecJson(Action.Refusal));

export const withHttp = <A, E>(
  effect: Effect.Effect<A, E, import("effect/http/HttpClient").HttpClient>,
) => effect.pipe(Effect.provide(FetchHttpClient.layer));

/**
 * How a caller proves it is a principal of the tests' resource, as a binding names it, and
 * what its verifier fails with when the issuer cannot be reached.
 */
export const Login = Authentication.make("notes.Login", CurrentPrincipal, {
  error: ProviderUnavailable,
});

/** The resource the tests declare: one service, built per test by `Notes.layer(options)`. */
export const Notes = Resource.make(Login, {
  scopes: ["notes:read", "notes:write"],
  required: "notes:read",
});

/** The application's own rule, which its implementations state: a write needs `notes:write`. */
export const authorize = (action: Action.Any) =>
  action.readOnly ? Effect.void : Notes.requires("notes:write");

/** A resource of `scopes`, built from `options`, for a test to call directly. */
export const resourceOf = <const Scope extends string>({
  scopes,
  required,
  ...options
}: Resource.Options & Resource.Declaration<Scope>) => {
  const declared = Resource.make(Login, { scopes, required });

  return Effect.provide(Effect.service(declared.service), declared.layer(options));
};

/** The published fake issuer, with a read-write key (`key-1`) and a read-only key (`key-2`). */
export const startIssuer = async (resource: string) => {
  const fake = await startFakeIssuer({ resource, scopes: ["notes:read", "notes:write"] });

  return { ...fake, key: fake.apiKey(), readOnlyKey: fake.apiKey({ [resource]: ["notes:read"] }) };
};

/** A key list as the issuer signs it: sealed entries, its `typ`, and the format's lifetime. */
export const signList = async (
  privateKey: CryptoKey,
  issuer: string,
  audience: string,
  grants: Iterable<readonly [string, KeyList.Grant]>,
  iat: number,
) =>
  new SignJWT({
    keys: await Promise.all(
      [...grants].map(async ([key, grant]) =>
        KeyList.seal(await KeyList.digest(key), audience, grant),
      ),
    ),
  })
    .setProtectedHeader({ alg: "EdDSA", kid: "fixture", typ: KeyList.type })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(iat)
    .setExpirationTime(iat + KeyList.lifetime)
    .sign(privateKey);
