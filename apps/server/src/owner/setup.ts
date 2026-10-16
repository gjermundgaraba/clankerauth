import { Context, Effect } from "effect";
import type { SetupInput } from "@gjermundgaraba/clankerauth-admin-api";
import { OwnerAccount } from "./owner.ts";

export class ResponseCookies extends Context.Service<
  ResponseCookies,
  { readonly add: (setCookie: Iterable<string>) => Effect.Effect<void> }
>()("clankerauth/ResponseCookies") {}

export const setupActions = Effect.map(OwnerAccount, (owner) => ({
  setupStatus: () => owner.find().pipe(Effect.map((found) => ({ required: !found }))),
  setupOwner: Effect.fn("Administration.setup")(function* (input: typeof SetupInput.Type) {
    const cookies = yield* owner.create(input);

    yield* (yield* ResponseCookies).add(cookies);

    return { created: true };
  }),
}));
