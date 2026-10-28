import { Data, Schema } from "effect";

import type { Principal } from "./verify.ts";

/**
 * The credential is missing, malformed, expired, revoked, or not this resource's: one cause,
 * so one message, `Authentication required`, unless another is given.
 */
export class Unauthorized extends Data.TaggedError("Unauthorized")<{
  readonly message: string;
}> {
  declare readonly cause?: unknown;

  constructor(
    options: { readonly message?: string; readonly cause?: unknown } = {}
  ) {
    super({ message: options.message ?? "Authentication required" });
    Object.defineProperty(this, "cause", { value: options.cause });
  }
}

/**
 * The issuer could not be reached, so the credential could not be decided: a 503, not a
 * refusal. A resource's descriptor declares it,
 * `Authentication.make("notes.Login", CurrentPrincipal, { error: ProviderUnavailable })`.
 * Its public response is the schema. Diagnostic causes are internal, non-enumerable fields.
 */
export class ProviderUnavailable extends Schema.TaggedError<
  ProviderUnavailable,
  { readonly brand: unique symbol }
>()(
  "ProviderUnavailable",
  { operation: Schema.String },
  { httpApiStatus: 503 }
) {
  declare readonly cause?: unknown;

  static readonly of = (operation: string, cause: unknown) =>
    Object.defineProperty(new ProviderUnavailable({ operation }), "cause", {
      value: cause,
    });
}

/**
 * A verified credential lacks one of the verifier's `requiredScopes`, a resource's `required`:
 * the only check failing with it, as `requires`, `admitted`, `admit` and `watch` refuse with
 * `Action.Forbidden` directly. It names only the missing scope, so a refusal never enumerates
 * the resource's permissions, and the credential's `actor`, which decides whether the caller
 * can step up to it.
 */
export class InsufficientScope extends Data.TaggedError("InsufficientScope")<{
  readonly scope: string;
  readonly actor: Principal["actor"];
}> {}

export class ConfigurationError extends Schema.TaggedError<
  ConfigurationError,
  { readonly brand: unique symbol }
>()("ConfigurationError", { message: Schema.String }) {}

/** What verification fails with. */
export type AuthenticationError =
  | Unauthorized
  | InsufficientScope
  | ProviderUnavailable;
