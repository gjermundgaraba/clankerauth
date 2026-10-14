import { Effect, Schema } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { FetchHttpClient } from "effect/http";
import { SignJWT } from "jose";
import * as KeyList from "../src/key-list.ts";
import { Resource } from "../src/effect-actions.ts";
import { CurrentPrincipal } from "../src/session.ts";
import { ProviderUnavailable } from "../src/errors.ts";
import { startFakeIssuer, type FakeIssuerOptions } from "../src/testing.ts";

export const publicUrl = "http://127.0.0.1:7337";

export const sent = Schema.encodeSync(Schema.toCodecJson(Action.Refusal));

export const withHttp = <A, E>(
  effect: Effect.Effect<A, E, import("effect/http/HttpClient").HttpClient>,
) => effect.pipe(Effect.provide(FetchHttpClient.layer));

export const Login = Authentication.make("notes.Login", CurrentPrincipal, {
  error: ProviderUnavailable,
});

export const Notes = Resource.make(Login, {
  scopes: ["notes:read", "notes:write"],
  required: "notes:read",
});

export const authorize = (action: Action.Any) =>
  action.readOnly ? Effect.void : Notes.requires("notes:write");

export const resourceOf = <const Scope extends string>({
  scopes,
  required,
  ...options
}: Resource.Options & Resource.Declaration<Scope>) => {
  const declared = Resource.make(Login, { scopes, required });

  return Effect.provide(Effect.service(declared.service), declared.layer(options));
};

export const fakeIssuer = (options: FakeIssuerOptions) =>
  Effect.acquireRelease(
    Effect.promise(() => startFakeIssuer(options)),
    (fake) => Effect.promise(() => fake.close()),
  );

export const startIssuer = (resource: string) =>
  Effect.map(fakeIssuer({ resource, scopes: ["notes:read", "notes:write"] }), (fake) => ({
    ...fake,
    key: fake.apiKey(),
    readOnlyKey: fake.apiKey({ [resource]: ["notes:read"] }),
  }));

export const webHandler = <Web extends { readonly dispose: () => Promise<void> }>(
  build: () => Web,
) => Effect.acquireRelease(Effect.sync(build), (web) => Effect.promise(() => web.dispose()));

export const json = (response: Response) => Effect.promise(() => response.json());

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
