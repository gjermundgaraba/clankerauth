import {
  ClientIsAutomatic,
  ClientNotFound,
} from "@gjermundgaraba/clankerauth-admin-api";
import { Effect, Schema } from "effect";

import { persisted } from "../platform/sqlite.ts";
import type { Sql } from "../platform/sqlite.ts";

export const isAutomatic = (client: { readonly userId: string | null }) =>
  client.userId === null;

const clientOwners = persisted(
  Schema.Array(Schema.Struct({ userId: Schema.NullOr(Schema.String) }))
);

export const requireManaged = Effect.fn("Clients.requireManaged")(function* (
  clientId: string,
  query: Sql
) {
  const [client] = yield* clientOwners(
    yield* query`SELECT userId FROM oauthClient WHERE clientId = ${clientId}`
  );

  if (!client) {
    return yield* ClientNotFound.of(clientId);
  }

  if (isAutomatic(client)) {
    return yield* ClientIsAutomatic.of(clientId);
  }
});
