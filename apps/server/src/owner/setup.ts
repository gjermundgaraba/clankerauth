import { Effect } from "effect";
import { InternalServerError, type SetupInput } from "@clankerauth/admin-api";
import { ResponseCookies } from "../http/response-cookies.ts";
import { OwnerAccount } from "./owner.ts";

/** The issuer's public setup actions: whether an owner is needed, and creating one. */
export const setupActions = Effect.map(OwnerAccount, (owner) => ({
  setupStatus: () =>
    owner.find().pipe(
      Effect.map((found) => ({ required: !found })),
      Effect.mapError(() => new InternalServerError({ error: "Request could not be completed" })),
    ),
  setupOwner: Effect.fn("Administration.setup")(function* (input: typeof SetupInput.Type) {
    const cookies = yield* owner.create(input);

    yield* (yield* ResponseCookies).add(cookies);

    return { created: true };
  }),
}));
