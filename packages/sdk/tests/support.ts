import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import type { Duration } from "effect";
import { Clock, Deferred, Effect, Schema } from "effect";
import { FetchHttpClient, HttpClient, HttpClientResponse } from "effect/http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

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

export const grantOf = (
  scopes: string[],
  expiresAt: number | null = null
): KeyList.Grant => ({ keyId: "key", ownerId: "owner", scopes, expiresAt });

/** What the in-memory issuer does next: fail with 503, wait for `hold`, or answer late. */
export interface Upstream {
  unavailable: boolean;
  hold: Deferred.Deferred<undefined> | undefined;
  latency: { jwks?: Duration.Input; lists?: Duration.Input };
}

/**
 * An issuer served from memory on the test clock: it signs a key list of `granted`, as it
 * stands, at every read, counts its reads before answering, and does what `upstream` says.
 */
export const listIssuer = (
  grants: Iterable<readonly [string, KeyList.Grant]>
) =>
  Effect.gen(function* () {
    const issuer = "https://issuer.example/api/auth";
    const audience = "https://notes.example/";

    const pair = yield* Effect.promise(
      async () => await generateKeyPair("EdDSA")
    );

    const jwk = {
      ...(yield* Effect.promise(async () => await exportJWK(pair.publicKey))),
      kid: "fixture",
      alg: "EdDSA",
    };

    const granted = new Map(grants);
    const reads = { jwks: 0, lists: 0 };

    const upstream: Upstream = {
      unavailable: false,
      hold: undefined,
      latency: {},
    };

    const client = HttpClient.make((request) =>
      Effect.gen(function* () {
        const jwks = request.url.endsWith("/jwks");
        reads[jwks ? "jwks" : "lists"] += 1;

        const { unavailable, hold } = upstream;

        if (hold !== undefined) {
          yield* Deferred.await(hold);
        }

        const latency = upstream.latency[jwks ? "jwks" : "lists"];

        if (latency !== undefined) {
          yield* Effect.sleep(latency);
        }

        if (unavailable) {
          return HttpClientResponse.fromWeb(
            request,
            new Response("{}", { status: 503 })
          );
        }

        if (jwks) {
          return HttpClientResponse.fromWeb(
            request,
            Response.json({ keys: [jwk] })
          );
        }

        const seconds = Math.floor((yield* Clock.currentTimeMillis) / 1000);

        const list = yield* Effect.promise(
          async () =>
            await signList(
              pair.privateKey,
              issuer,
              audience,
              new Map(granted),
              seconds
            )
        );

        return HttpClientResponse.fromWeb(request, Response.json({ list }));
      })
    );

    const token = Effect.flatMap(Clock.currentTimeMillis, (now) =>
      Effect.promise(
        async () =>
          await new SignJWT({ client_id: "web", scope: "read" })
            .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid: "fixture" })
            .setIssuer(issuer)
            .setAudience(audience)
            .setSubject("owner")
            .setIssuedAt(Math.floor(now / 1000))
            .setExpirationTime(Math.floor(now / 1000) + 3600)
            .sign(pair.privateKey)
      )
    );

    return {
      issuer,
      audience,
      pair,
      jwk,
      granted,
      reads,
      upstream,
      client,
      token,
    };
  });
