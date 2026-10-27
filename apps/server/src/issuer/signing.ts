import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { signJWT } from "better-auth/plugins/jwt";
import type { JwtOptions } from "better-auth/plugins/jwt";
import { Schema } from "effect";

const SignRequest = Schema.toStandardSchemaV1(
  Schema.Struct({
    typ: Schema.String,
    payload: Schema.Record(Schema.String, Schema.Json),
  })
);

export const signer = (jwt: JwtOptions) =>
  ({
    id: "signer",
    endpoints: {
      signDocument: createAuthEndpoint.serverOnly(
        { method: "POST", body: SignRequest },
        async (ctx) =>
          await ctx.json({
            token: await signJWT(ctx, {
              options: jwt,
              header: { typ: ctx.body.typ },
              payload: ctx.body.payload,
            }),
          })
      ),
    },
  }) satisfies BetterAuthPlugin;
