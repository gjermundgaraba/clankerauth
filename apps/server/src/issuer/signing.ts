import { Schema } from "effect";
import { createAuthEndpoint } from "better-auth/api";
import type { BetterAuthPlugin } from "better-auth";
import { signJWT, type JwtOptions } from "better-auth/plugins/jwt";

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
