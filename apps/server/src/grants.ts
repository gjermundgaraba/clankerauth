import { Effect } from "effect";
import type { Sql } from "./database.ts";

/**
 * The consent reference of one resource. Every consent, authorization code and token
 * carries the reference it was authorized under, so authorization is cleared per resource.
 */
export const resourceReference = (identifier: string) => `${referencePrefix}${identifier}`;

/** A reference is this prefix and the identifier, so SQL can join grants to resources. */
export const referencePrefix = "resource:";

/** Pending authorization codes live in the verification table, outside the client's
 * foreign keys, so nothing cascades to them. */
export const clearCodes = (query: Sql, clientId: string | null, reference: string | null) =>
  query`DELETE FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND (${clientId} IS NULL OR json_extract(value, '$.query.client_id') = ${clientId}) AND (${reference} IS NULL OR json_extract(value, '$.referenceId') = ${reference})`;

/**
 * Clears stored authorization: a client's, a resource's, or one client's for one
 * resource. The provider has no bulk revocation API, so this stays local SQL.
 */
export const clearGrants = Effect.fn("Grants.clear")(function* (
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
