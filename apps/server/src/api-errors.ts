import { APIError } from "better-auth/api";
import {
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
