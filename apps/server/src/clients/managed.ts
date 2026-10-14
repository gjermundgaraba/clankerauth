import { Effect, Schema } from "effect";
import { ClientIsAutomatic, ClientNotFound } from "@clankerauth/admin-api";
import { persisted, type Sql } from "../platform/sqlite.ts";

// why: a client that registered itself, through DCR or CIMD, has no owning user
export const isAutomatic = (client: { readonly userId: string | null }) => client.userId === null;

const clientOwners = persisted(
  Schema.Array(Schema.Struct({ userId: Schema.NullOr(Schema.String) })),
);

export const requireManaged = Effect.fn("Clients.requireManaged")(function* (
  clientId: string,
  query: Sql,
) {
  const [client] = yield* clientOwners(
    yield* query`SELECT userId FROM oauthClient WHERE clientId = ${clientId}`,
  );

  if (!client) return yield* Effect.fail(ClientNotFound.of(clientId));

  if (isAutomatic(client)) return yield* Effect.fail(ClientIsAutomatic.of(clientId));
});
