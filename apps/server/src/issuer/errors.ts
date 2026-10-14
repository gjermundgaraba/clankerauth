import { Effect, Option, Predicate, Schema, SchemaAST } from "effect";
import { HttpServerError, HttpServerResponse } from "effect/http";
import { type APIError, isAPIError } from "better-auth/api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import {
  errors,
  InternalServerError,
  ProviderRefused,
  ServiceUnavailable,
  UnreadableRequest,
  type IssuerError,
} from "@clankerauth/admin-api";

// why: Better Auth core errors carry `message`; its OAuth provider sends `error_description`
const ProviderErrorBody = Schema.Struct({
  message: Schema.optionalKey(Schema.String),
  error_description: Schema.optionalKey(Schema.String),
});

const describe = Schema.decodeUnknownOption(ProviderErrorBody);

const sentence = (cause: APIError) =>
  Option.getOrElse(
    Option.flatMap(describe(cause.body), (body) =>
      Option.fromNullishOr(body.message ?? body.error_description),
    ),
    () => "Request could not be completed",
  );

export const refusal = (message: string) => new ProviderRefused({ message });

export const unavailability = (message: string) => new ServiceUnavailable({ message });

/** What the caller makes of each provider status; any other failure is `InternalServerError`. */
export interface ProviderMeanings<Refused, Missing, Conflict, Unavailable> {
  /** 400 or 422: the provider refused the input on a rule of its own. */
  readonly refused?: (message: string) => Refused;
  /** 404: the subject does not exist. */
  readonly missing?: (message: string) => Missing;
  /** 409: the request conflicts with stored state. */
  readonly conflict?: (message: string) => Conflict;
  /** 503: the provider cannot decide now. */
  readonly unavailable?: (message: string) => Unavailable;
}

export const provider = <
  A,
  Refused = never,
  Missing = never,
  Conflict = never,
  Unavailable = never,
>(
  operation: () => Promise<A>,
  meanings: ProviderMeanings<Refused, Missing, Conflict, Unavailable> = {},
): Effect.Effect<A, InternalServerError | Refused | Missing | Conflict | Unavailable> =>
  Effect.tryPromise({
    try: operation,
    catch: (cause) => {
      if (!isAPIError(cause)) return InternalServerError.of(cause);
      const status = cause.statusCode;

      const meaning =
        status === 400 || status === 422
          ? meanings.refused
          : status === 404
            ? meanings.missing
            : status === 409
              ? meanings.conflict
              : status === 503
                ? meanings.unavailable
                : undefined;

      return meaning ? meaning(sentence(cause)) : InternalServerError.of(cause);
    },
  });

export const invalidInput = (path: Action.Issue["path"], message: string) =>
  new Action.InvalidInput({ message, issues: [{ path, message }] });

const isIssuerError = Schema.is(Schema.Union(errors));

const isRequestParseError = Predicate.isTagged("RequestParseError");

const routeError = (cause: unknown): IssuerError => {
  if (isIssuerError(cause)) return cause;

  if (HttpServerError.isHttpServerError(cause) && isRequestParseError(cause.reason))
    return new UnreadableRequest({ message: "Request body could not be read" });

  return InternalServerError.of(cause);
};

const statuses = new Map<unknown, number>(
  errors.map(
    (schema) => [schema, SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500] as const,
  ),
);

const encodeResponse = HttpServerResponse.schemaJson(Schema.Union(errors));

export const respond = (cause: unknown) => {
  const error = routeError(cause);
  const schema = errors.find((candidate) => Schema.is(candidate)(error));

  return encodeResponse(error, { status: statuses.get(schema) ?? 500 }).pipe(Effect.orDie);
};
