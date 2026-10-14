import { Effect, Option, Predicate, Schema, SchemaAST } from "effect";
import { HttpServerError, HttpServerResponse } from "effect/http";
import { type APIError, isAPIError } from "better-auth/api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import {
  ownerErrors,
  BadRequest,
  Conflict,
  InternalServerError,
  NotFound,
  ServiceUnavailable,
  TooManyRequests,
} from "@clankerauth/admin-api";
import type { OwnerError } from "@clankerauth/admin-api";

const statuses = new Map<unknown, number>(
  ownerErrors.map(
    (schema) => [schema, SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500] as const,
  ),
);

const isOwnerError = (cause: unknown): cause is OwnerError =>
  ownerErrors.some((schema) => Schema.is(schema)(cause));

/** This issuer's own fault: a failed query, an unreadable row, an unexpected rejection. */
export const internalError = (cause: unknown) => {
  const error = new InternalServerError({ error: "Request could not be completed" });
  error.cause = cause;

  return error;
};

// Better Auth core errors carry `message`; the OAuth provider uses `error_description`.
const ProviderErrorBody = Schema.Struct({
  message: Schema.optionalKey(Schema.String),
  error_description: Schema.optionalKey(Schema.String),
});

const describe = Schema.decodeUnknownOption(ProviderErrorBody);

const providerBody = (cause: APIError) => ({
  error: Option.getOrElse(
    Option.flatMap(describe(cause.body), (value) =>
      Option.fromNullishOr(value.message ?? value.error_description),
    ),
    () => "Request could not be completed",
  ),
});

/**
 * Every refusal this issuer answers with is administration's own, an `OwnerError`. Domain code
 * fails with these directly; only foreign failures — the provider SDK, SQLite, a persisted row —
 * are translated, here. Idempotent: already-public errors pass through unchanged.
 */
export function apiError(cause: unknown): OwnerError {
  if (isOwnerError(cause)) return cause;

  if (isAPIError(cause)) {
    const body = providerBody(cause);

    switch (cause.statusCode) {
      case 400:
      case 422:
        return new BadRequest(body);
      // Owner routes are already authenticated: a provider 401 refuses an operation.
      case 401:
      case 403:
        return new Action.Forbidden({ message: body.error });
      case 404:
        return new NotFound(body);
      case 409:
        return new Conflict(body);
      case 429:
        return new TooManyRequests(body);
      case 503:
        return new ServiceUnavailable(body);
    }
  }

  // A request body this issuer could not read — truncated, oversized, an abandoned
  // upload — is the caller's, not a failure of its own.
  if (HttpServerError.isHttpServerError(cause) && isRequestParseError(cause.reason))
    return new BadRequest({ error: "Request body could not be read" });

  return internalError(cause);
}

const isRequestParseError = Predicate.isTagged("RequestParseError");

/**
 * Input that decodes but cannot be served: effect-actions' built-in 400, which every endpoint
 * and tool declares, naming the field at fault.
 */
export const invalidInput = (path: Action.Issue["path"], message: string) =>
  new Action.InvalidInput({ message, issues: [{ path, message }] });

/** Provider SDK calls fail with public API errors. */
export const provider = <A>(operation: () => Promise<A>) =>
  Effect.tryPromise({ try: operation, catch: apiError });

const encodeResponse = HttpServerResponse.schemaJson(Schema.Union(ownerErrors));

/** Encode only public error fields, with the error's own status. */
export const apiErrorResponse = (error: OwnerError) => {
  const schema = ownerErrors.find((schema) => Schema.is(schema)(error));

  if (schema === undefined) return Effect.die(new Error("Undeclared API error"));

  return encodeResponse(error, { status: statuses.get(schema) ?? 500 }).pipe(Effect.orDie);
};

/** Translate whatever a route failed with, once, into its public response. */
export const respond = (cause: unknown) => apiErrorResponse(apiError(cause));
