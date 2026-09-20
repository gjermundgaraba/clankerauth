import { Effect, Schema, SchemaAST } from "effect";
import { type Headers, HttpServerResponse } from "effect/unstable/http";

/** Schemas define public responses. Diagnostic causes are internal, non-enumerable fields. */
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

export class Forbidden extends Schema.TaggedError<Forbidden>()(
  "Forbidden",
  { message: Schema.String },
  { httpApiStatus: 403 },
) {}

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

export class StoreError extends Schema.TaggedError<StoreError>()(
  "StoreError",
  { operation: Schema.String },
  { httpApiStatus: 503 },
) {
  declare readonly cause?: unknown;

  constructor(options: { readonly operation: string; readonly cause?: unknown }) {
    super({ operation: options.operation });
    Object.defineProperty(this, "cause", { value: options.cause });
  }
}

export class InvalidRequest extends Schema.TaggedError<InvalidRequest>()(
  "InvalidRequest",
  { message: Schema.String },
  { httpApiStatus: 400 },
) {}

export class ConfigurationError extends Schema.TaggedError<ConfigurationError>()(
  "ConfigurationError",
  { message: Schema.String },
) {}

export const authenticationErrors = [
  Unauthorized,
  Forbidden,
  RateLimited,
  ProviderUnavailable,
  StoreError,
] as const;

export type AuthenticationError =
  | Unauthorized
  | Forbidden
  | RateLimited
  | ProviderUnavailable
  | StoreError;

/** Encode one of the declared schemas as JSON with its `httpApiStatus`. Undeclared errors are defects. */
export const encodeError = <const Schemas extends ReadonlyArray<Schema.Top>>(schemas: Schemas) => {
  const encode = HttpServerResponse.schemaJson(Schema.Union(schemas));

  return (error: Schemas[number]["Type"], headers?: Headers.Input) => {
    const schema = schemas.find((schema) => Schema.is(schema)(error));

    if (schema === undefined) return Effect.die(new Error("Undeclared error"));

    return encode(error, {
      status: SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500,
      headers,
    }).pipe(Effect.orDie);
  };
};
