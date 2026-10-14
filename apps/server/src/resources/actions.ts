import { Effect } from "effect";
import { CurrentOwner, type Resource, type ResourceId } from "@clankerauth/admin-api";
import { Auth } from "../issuer/issuer.ts";

export const resourceActions = Effect.map(Auth, (service) => ({
  createResource: Effect.fn("Administration.createResource")(function* (
    input: typeof Resource.Type,
  ) {
    const { providerHeaders } = yield* CurrentOwner;
    const headers = yield* providerHeaders;

    return yield* service.resources.create(input, headers);
  }),
  updateResource: Effect.fn("Administration.updateResource")(function* (
    input: typeof Resource.Type,
  ) {
    const { providerHeaders } = yield* CurrentOwner;
    const headers = yield* providerHeaders;

    return yield* service.resources.update(input, headers);
  }),
  deleteResource: Effect.fn("Administration.deleteResource")(function* (
    input: typeof ResourceId.Type,
  ) {
    const { providerHeaders } = yield* CurrentOwner;
    const headers = yield* providerHeaders;

    return yield* service.resources.delete(input.identifier, headers);
  }),
}));
