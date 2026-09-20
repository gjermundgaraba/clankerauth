import { Effect, Schema, SchemaAST } from "effect";
import { type Headers, HttpServerResponse } from "effect/unstable/http";
import { isAPIError } from "better-auth/api";
import {
  errors,
  BadRequest,
  Conflict,
  Forbidden,
  InternalServerError,
  NotFound,
  ServiceUnavailable,
  TooManyRequests,
  Unauthorized,
} from "@clankerauth/api";

const isApiError = (cause: unknown): cause is (typeof errors)[number]["Type"] =>
  errors.some((schema) => Schema.is(schema)(cause));

/** Idempotent: already-public errors pass through unchanged. */
export function apiError(cause: unknown) {
  if (isApiError(cause)) return cause;

  if (isAPIError(cause)) {
    const body = { error: cause.body?.message ?? "Request could not be completed" };

    switch (cause.statusCode) {
      case 400:
        return new BadRequest(body);
      case 401:
        return new Unauthorized({ error: "Authentication required" });
      case 403:
        return new Forbidden(body);
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

  return new InternalServerError({ error: "Request could not be completed" });
}

/** Provider SDK calls fail with public API errors. */
export const provider = <A>(operation: () => Promise<A>) =>
  Effect.tryPromise({ try: operation, catch: apiError });

const encodeResponse = HttpServerResponse.schemaJson(Schema.Union(errors));

/** Encode only public error fields; callers own request-specific challenge headers. */
export const apiErrorResponse = (
  error: (typeof errors)[number]["Type"],
  headers: Headers.Input = {},
) => {
  const schema = errors.find((schema) => Schema.is(schema)(error));

  if (schema === undefined) return Effect.die(new Error("Undeclared API error"));

  return encodeResponse(error, {
    status: SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500,
    headers,
  }).pipe(Effect.orDie);
};
