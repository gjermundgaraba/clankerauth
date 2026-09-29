/**
 * Signs JWTs outside the OAuth flows — forward-auth access tokens and key lists — with the
 * JWT plugin's key, so a resource server verifies every one against the same JWKS. The
 * caller supplies the header type and the whole payload, `aud`, `iat` and `exp` included;
 * the plugin adds `iss`. Server-only: never routed.
 */
import { Schema } from "effect";
import { createAuthEndpoint } from "better-auth/api";
import type { BetterAuthPlugin } from "better-auth";
import { signJWT, type JwtOptions } from "better-auth/plugins/jwt";

/** The provider validates endpoint bodies through the Standard Schema interface. */
const SignRequest = Schema.toStandardSchemaV1(
  Schema.Struct({ typ: Schema.String, payload: Schema.Record(Schema.String, Schema.Json) }),
);

export const signer = (jwt: JwtOptions) =>
  ({
    id: "signer",
    endpoints: {
      signDocument: createAuthEndpoint.serverOnly(
        { method: "POST", body: SignRequest },
        async (ctx) =>
          ctx.json({
            token: await signJWT(ctx, {
              options: jwt,
              header: { typ: ctx.body.typ },
              payload: ctx.body.payload,
            }),
          }),
      ),
    },
  }) satisfies BetterAuthPlugin;
