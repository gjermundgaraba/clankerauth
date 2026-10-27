import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { Effect, Schema } from "effect";
import { FetchHttpClient } from "effect/http";
import type { HttpClient } from "effect/http";
import { SignJWT } from "jose";

import { Resource } from "../src/effect-actions.ts";
import { ProviderUnavailable } from "../src/errors.ts";
import * as KeyList from "../src/key-list.ts";
import { CurrentPrincipal } from "../src/session.ts";
import { startFakeIssuer } from "../src/testing.ts";
import type { FakeIssuerOptions } from "../src/testing.ts";

export const publicUrl = "http://127.0.0.1:7337";

export const sent = Schema.encodeSync(Schema.toCodecJson(Action.Refusal));

export const withHttp = <A, E>(
  effect: Effect.Effect<A, E, HttpClient.HttpClient>
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

  return Effect.provide(
    Effect.service(declared.service),
    declared.layer(options)
  );
};

export const fakeIssuer = (options: FakeIssuerOptions) =>
  Effect.acquireRelease(
    Effect.promise(async () => await startFakeIssuer(options)),
    (fake) =>
      Effect.promise(async () => {
        await fake.close();
      })
  );

export const startIssuer = (resource: string) =>
  Effect.map(
    fakeIssuer({ resource, scopes: ["notes:read", "notes:write"] }),
    (fake) => ({
      ...fake,
      key: fake.apiKey(),
      readOnlyKey: fake.apiKey({ [resource]: ["notes:read"] }),
    })
  );

export const webHandler = <
  Web extends { readonly dispose: () => Promise<void> },
>(
  build: () => Web
) =>
  Effect.acquireRelease(Effect.sync(build), (web) =>
    Effect.promise(async () => {
      await web.dispose();
    })
  );

export const json = (response: Response) =>
  Effect.flatMap(
    Effect.promise(async () => await response.text()),
    Schema.decodeEffect(Schema.fromJsonString(Schema.Json))
  );

export const signList = async (
  privateKey: CryptoKey,
  issuer: string,
  audience: string,
  grants: Iterable<readonly [string, KeyList.Grant]>,
  iat: number
) =>
  await new SignJWT({
    keys: await Promise.all(
      [...grants].map(
        async ([key, grant]) =>
          await KeyList.seal(await KeyList.digest(key), audience, grant)
      )
    ),
  })
    .setProtectedHeader({ alg: "EdDSA", kid: "fixture", typ: KeyList.type })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(iat)
    .setExpirationTime(iat + KeyList.lifetime)
    .sign(privateKey);
