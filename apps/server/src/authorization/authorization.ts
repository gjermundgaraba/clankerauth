import { Effect } from "effect";
import type { Sql } from "../platform/sqlite.ts";

export const resourceReference = (identifier: string) => `${referencePrefix}${identifier}`;

export const referencePrefix = "resource:";

// why: codes live in the verification table, outside the client's foreign keys, so nothing cascades
export const clearCodes = (query: Sql, clientId: string | null, reference: string | null) =>
  query`DELETE FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND (${clientId} IS NULL OR json_extract(value, '$.query.client_id') = ${clientId}) AND (${reference} IS NULL OR json_extract(value, '$.referenceId') = ${reference})`;

// why: the provider has no bulk revocation API
export const clearAuthorization = Effect.fn("Authorization.clear")(function* (
  query: Sql,
  selection: { readonly clientId?: string; readonly resource?: string },
) {
  const client = selection.clientId ?? null;
  const reference = selection.resource === undefined ? null : resourceReference(selection.resource);
  yield* query`DELETE FROM oauthConsent WHERE (${client} IS NULL OR clientId = ${client}) AND (${reference} IS NULL OR referenceId = ${reference})`;
  yield* clearCodes(query, client, reference);
  yield* query`DELETE FROM oauthAccessToken WHERE (${client} IS NULL OR clientId = ${client}) AND (${reference} IS NULL OR referenceId = ${reference})`;
  yield* query`DELETE FROM oauthRefreshToken WHERE (${client} IS NULL OR clientId = ${client}) AND (${reference} IS NULL OR referenceId = ${reference})`;
});
