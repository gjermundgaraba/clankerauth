import { Effect, Schema, SchemaAST } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { APIError } from "better-auth/api";
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

export function apiError(cause: unknown) {
  if (cause instanceof APIError) {
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

const encodeResponse = HttpServerResponse.schemaJson(Schema.Union(errors));

/** Encode only public error fields; callers own request-specific challenge headers. */
export const apiErrorResponse = (
  error: (typeof errors)[number]["Type"],
  headers: Readonly<Record<string, string>> = {},
) => {
  const schema = errors.find((schema) => Schema.is(schema)(error));

  if (schema === undefined) return Effect.die(new Error("Undeclared API error"));

  return encodeResponse(error, {
    status: SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500,
    headers,
  }).pipe(Effect.orDie);
};
