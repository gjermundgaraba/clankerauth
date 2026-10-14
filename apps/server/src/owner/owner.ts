import { Context, Effect, Layer, Schema, Scope, Semaphore } from "effect";
import { Conflict, type Owner, type OwnerError } from "@clankerauth/admin-api";
import { Database, persisted } from "../platform/sqlite.ts";
import { provider } from "../issuer/errors.ts";
import { Issuer } from "../issuer/issuer.ts";
import { Settings } from "../issuer/settings.ts";
import { providerSessionFor } from "./provider-session.ts";

const decodeOwnerRow = persisted(Schema.Struct({ id: Schema.String }));

/** The sole account: who it is, how setup creates it, and how administration acts as it. */
export class OwnerAccount extends Context.Service<
  OwnerAccount,
  {
    /** Setup creates the only account, so the owner is whichever user exists. */
    readonly find: () => Effect.Effect<string | undefined, OwnerError>;
    /**
     * First-run setup is the only sign-up: the provider route is not mounted, and the
     * user-creation hook refuses a second account. Setup requests are serialized so a
     * concurrent one sees the created owner and gets a conflict. The provider signs
     * the owner in; the returned cookies belong on the response.
     */
    readonly create: (input: {
      readonly email: string;
      readonly password: string;
    }) => Effect.Effect<string[], OwnerError>;
    /** A temporary provider session for `userId`, deleted when the calling scope closes. */
    readonly providerSession: (userId: string) => Effect.Effect<Headers, OwnerError, Scope.Scope>;
    /** The owner as administration's caller, acting through a temporary provider session. */
    readonly caller: (userId: string, email: string, writable: boolean) => Owner;
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

      const find = Effect.fn("Owner.find")(function* () {
        const rows = yield* sql`SELECT id FROM user LIMIT 1`;

        if (!rows.length) return undefined;

        return (yield* decodeOwnerRow(rows[0])).id;
      });

      return {
        find,
        create: Effect.fn("Owner.create")(
          function* (input: { readonly email: string; readonly password: string }) {
            if (yield* find())
              return yield* Effect.fail(new Conflict({ error: "Setup already completed" }));

            const { headers } = yield* provider(() =>
              auth.api.signUpEmail({
                body: { name: "Owner", email: input.email.trim(), password: input.password },
                returnHeaders: true,
              }),
            );

            return headers.getSetCookie();
          },
          (effect) => setup.withPermit(effect),
        ),
        providerSession,
        caller: (userId, email, writable) => ({
          userId,
          email,
          writable,
          providerHeaders: providerSession(userId),
        }),
      };
    }),
  );
}
