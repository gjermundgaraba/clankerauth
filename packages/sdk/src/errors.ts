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

export const authenticationErrors = [
  Unauthorized,
  Forbidden,
  RateLimited,
  ProviderUnavailable,
] as const;

export type AuthenticationError = Unauthorized | Forbidden | RateLimited | ProviderUnavailable;

/** What `Resource.admit` may refuse with: verification, plus the write-scope check. */
export const admissionErrors = [...authenticationErrors, InsufficientScope] as const;

export type AdmissionError = AuthenticationError | InsufficientScope;

/** An error schema: service-free, so encoding a refusal needs no request context. */
export type ErrorSchema = Schema.Codec<unknown, unknown, never, never>;

/** One declared error as a status and a JSON body. Undeclared errors are defects. */
export const describeError = <const Schemas extends ReadonlyArray<ErrorSchema>>(
  schemas: Schemas,
) => {
  const encoders = new Map(
    schemas.map((schema) => [
      schema,
      {
        status: SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500,
        encode: Schema.encodeUnknownEffect(Schema.toCodecJson(schema)),
      },
    ]),
  );

  return (error: Schemas[number]["Type"]) => {
    const schema = schemas.find((candidate) => Schema.is(candidate)(error));
    const encoder = schema === undefined ? undefined : encoders.get(schema);

    if (encoder === undefined) return Effect.die(new Error("Undeclared error"));

    return Effect.map(Effect.orDie(encoder.encode(error)), (body) => ({
      status: encoder.status,
      body: JSON.stringify(body),
    }));
  };
};

/** Encode one of the declared schemas as a JSON response with its `httpApiStatus`. */
export const encodeError = <const Schemas extends ReadonlyArray<ErrorSchema>>(schemas: Schemas) => {
  const describe = describeError(schemas);

  return (error: Schemas[number]["Type"], headers?: Headers.Input) =>
    Effect.map(describe(error), ({ status, body }) =>
      HttpServerResponse.text(body, { status, headers, contentType: "application/json" }),
    );
};
