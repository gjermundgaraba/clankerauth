import { OwnerExists } from "@gjermundgaraba/clankerauth-admin-api";
import type {
  InternalServerError,
  Owner,
  ProviderRefused,
} from "@gjermundgaraba/clankerauth-admin-api";
import { Context, Effect, Layer, Schema, Semaphore } from "effect";

import { provider, refusal } from "../issuer/errors.ts";
import { Issuer } from "../issuer/issuer.ts";
import { Settings } from "../issuer/settings.ts";
import { Database, persisted } from "../platform/sqlite.ts";
import { providerSessionFor } from "./provider-session.ts";

const decodeOwnerRow = persisted(Schema.Struct({ id: Schema.String }));

export class OwnerAccount extends Context.Service<
  OwnerAccount,
  {
    /** Setup creates the only account, so the owner is whichever user exists. */
    readonly find: Effect.Effect<string | undefined, InternalServerError>;
    /**
     * First-run setup is the only sign-up: the provider route is not mounted, and the
     * user-creation hook refuses a second account. Setup requests are serialized so a
     * concurrent one sees the created owner and gets a conflict. The provider signs
     * the owner in; the returned cookies belong on the response.
     */
    readonly create: (input: {
      readonly email: string;
      readonly password: string;
    }) => Effect.Effect<
      string[],
      OwnerExists | ProviderRefused | InternalServerError
    >;
    /** The owner as administration's caller, acting through a temporary provider session. */
    readonly caller: (
      userId: string,
      email: string,
      writable: boolean
    ) => Owner;
  }
>()("clankerauth/OwnerAccount") {
  static readonly layer = Layer.effect(
    OwnerAccount,
    Effect.gen(function* () {
      const { sql } = yield* Database;
      const { auth, context } = yield* Issuer;
      const { baseURL } = yield* Settings;
      const setup = yield* Semaphore.make(1);
      const providerSession = providerSessionFor(context, baseURL);

      const find = Effect.gen(function* () {
        const rows = yield* sql`SELECT id FROM user LIMIT 1`;

        if (!rows.length) {
          return;
        }

        return (yield* decodeOwnerRow(rows[0])).id;
      }).pipe(Effect.withSpan("OwnerAccount.find"));

      return {
        find,
        create: Effect.fn("OwnerAccount.create")(
          function* (input: {
            readonly email: string;
            readonly password: string;
          }) {
            // why: the provider refuses an existing email before its hook can answer a conflict
            if ((yield* find) !== undefined) {
              return yield* OwnerExists.of();
            }

            const { headers } = yield* provider(
              async () =>
                await auth.api.signUpEmail({
                  body: {
                    name: "Owner",
                    email: input.email.trim(),
                    password: input.password,
                  },
                  returnHeaders: true,
                }),
              { refused: refusal, conflict: OwnerExists.of }
            );

            return headers.getSetCookie();
          },
          (effect) => setup.withPermit(effect)
        ),
        caller: (userId, email, writable) => ({
          userId,
          email,
          writable,
          providerHeaders: providerSession(userId),
        }),
      };
    })
  );
}
