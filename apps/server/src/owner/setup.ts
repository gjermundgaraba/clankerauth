import { Effect } from "effect";
import type { SetupInput } from "@clankerauth/admin-api";
import { ResponseCookies } from "../http/response-cookies.ts";
import { OwnerAccount } from "./owner.ts";

export const setupActions = Effect.map(OwnerAccount, (owner) => ({
  setupStatus: () => owner.find().pipe(Effect.map((found) => ({ required: !found }))),
  setupOwner: Effect.fn("Administration.setup")(function* (input: typeof SetupInput.Type) {
    const cookies = yield* owner.create(input);

    yield* (yield* ResponseCookies).add(cookies);

    return { created: true };
  }),
}));
