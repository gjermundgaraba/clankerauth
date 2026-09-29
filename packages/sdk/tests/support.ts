import { Effect } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { SignJWT } from "jose";
import * as KeyList from "../src/key-list.ts";
import { startFakeIssuer } from "../src/testing.ts";

export const publicUrl = "http://127.0.0.1:7337";

export const withHttp = <A, E>(
  effect: Effect.Effect<A, E, import("effect/unstable/http/HttpClient").HttpClient>,
) => effect.pipe(Effect.provide(FetchHttpClient.layer));

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
