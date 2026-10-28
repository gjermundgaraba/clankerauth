import {
  ClientListResult,
  ApiKey,
} from "@gjermundgaraba/clankerauth-admin-api";
import { Effect, Schema } from "effect";
import { Query } from "foldkit/experimental";

import { issuer, toOwnerSentence } from "../../api.ts";

export const Listing = Schema.Struct({
  overview: ClientListResult,
  keys: Schema.Array(ApiKey),
});

export type Listing = typeof Listing.Type;

export const listingQuery = Query.define({
  name: "Listing",
  data: Listing,
  error: Schema.String,
  execute: Effect.all(
    {
      overview: issuer.listClients(),
      keys: Effect.map(issuer.listApiKeys(), ({ keys }) => keys),
    },
    { concurrency: "unbounded" }
  ).pipe(toOwnerSentence),
});
