import { ClientListResult, MachineKey } from "@clankerauth/admin-api";
import { Effect, Schema } from "effect";
import { Query } from "foldkit/experimental";

import { issuer, toOwnerSentence } from "../api.ts";

/** Everything the dashboard lists, read in one go after every saved change. */
export const Listing = Schema.Struct({
  overview: ClientListResult,
  keys: Schema.Array(MachineKey),
});

export type Listing = typeof Listing.Type;

/** The listing as last read, kept on show while it is read again. */
export const listingQuery = Query.define({
  name: "Listing",
  data: Listing,
  error: Schema.String,
  execute: Effect.all(
    {
      overview: issuer.listClients(),
      keys: Effect.map(issuer.listApiKeys(), ({ keys }) => keys),
    },
    { concurrency: "unbounded" },
  ).pipe(toOwnerSentence),
});
