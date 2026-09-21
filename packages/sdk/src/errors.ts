/**
 * Every refusal this package produces, as schemas. This entry point is browser-safe:
 * a shared contract declares these on its surface and a browser client decodes them,
 * without pulling token verification or its cryptography into the bundle.
 *
 * Schemas define public responses. Diagnostic causes are internal, non-enumerable fields.
 */
import { Schema } from "effect";

export class Unauthorized extends Schema.TaggedError<Unauthorized>()(
  "Unauthorized",
  { message: Schema.String },
  { httpApiStatus: 401 },
) {
  declare readonly cause?: unknown;

  constructor(options: { readonly message: string; readonly cause?: unknown }) {
    super({ message: options.message });
    Object.defineProperty(this, "cause", { value: options.cause });
  }
}

export class RateLimited extends Schema.TaggedError<RateLimited>()(
  "RateLimited",
  { message: Schema.String },
  { httpApiStatus: 429 },
) {}

export class ProviderUnavailable extends Schema.TaggedError<ProviderUnavailable>()(
  "ProviderUnavailable",
  { operation: Schema.String },
  { httpApiStatus: 503 },
) {
  declare readonly cause?: unknown;

  constructor(options: { readonly operation: string; readonly cause?: unknown }) {
    super({ operation: options.operation });
    Object.defineProperty(this, "cause", { value: options.cause });
  }
}

/**
 * A verified credential lacks one scope the requested access needs. It names only
 * the missing scope, so a refusal never enumerates the resource's permissions.
 */
export class InsufficientScope extends Schema.TaggedError<InsufficientScope>()(
  "InsufficientScope",
  { scope: Schema.String },
  { httpApiStatus: 403 },
) {}

export class ConfigurationError extends Schema.TaggedError<ConfigurationError>()(
  "ConfigurationError",
  { message: Schema.String },
) {}

/**
 * What verification, admission and the authorization hook refuse with — one list, so a
 * surface declares `errors: authenticationErrors` and answers every refusal the same way.
 */
export const authenticationErrors = [
  Unauthorized,
  InsufficientScope,
  RateLimited,
  ProviderUnavailable,
] as const;

export type AuthenticationError =
  | Unauthorized
  | InsufficientScope
  | RateLimited
  | ProviderUnavailable;
