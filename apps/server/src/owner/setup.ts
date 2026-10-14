import { Effect } from "effect";
import { Conflict, type SetupInput } from "@clankerauth/admin-api";
import { ResponseCookies } from "../http/response-cookies.ts";
import { provider } from "../issuer/errors.ts";
import { Auth } from "../issuer/issuer.ts";

/**
 * First-run setup is the only sign-up: the provider route is not mounted, and the
 * user-creation hook refuses a second account. Setup requests are serialized so a
 * concurrent one sees the created owner and gets a conflict. The provider signs
 * the owner in; the returned cookies belong on the response.
 */
export const createOwner = Effect.fn("Auth.createOwner")(
  function* (service: Auth["Service"], input: { email: string; password: string }) {
    if (yield* service.owner())
      return yield* Effect.fail(new Conflict({ error: "Setup already completed" }));

    const { headers } = yield* provider(() =>
      service.auth.api.signUpEmail({
        body: { name: "Owner", email: input.email.trim(), password: input.password },
        returnHeaders: true,
      }),
    );

    return headers.getSetCookie();
  },
  (effect, service) => service.setup.withPermit(effect),
);

/** The setup action: create the owner, and sign them in on this response. */
export const setupActions = Effect.map(Auth, (service) => ({
  setupOwner: Effect.fn("Administration.setup")(function* (input: typeof SetupInput.Type) {
    const cookies = yield* createOwner(service, input);

    yield* (yield* ResponseCookies).add(cookies);

    return { created: true };
  }),
}));
