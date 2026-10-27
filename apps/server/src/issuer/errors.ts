import {
  errors,
  InternalServerError,
  ProviderRefused,
  ServiceUnavailable,
  UnreadableRequest,
} from "@gjermundgaraba/clankerauth-admin-api";
import type { IssuerError } from "@gjermundgaraba/clankerauth-admin-api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import { isAPIError } from "better-auth/api";
import type { APIError } from "better-auth/api";
import { Data, Effect, Option, Predicate, Schema, SchemaAST } from "effect";
import { HttpServerError, HttpServerResponse } from "effect/http";

// why: Better Auth core errors carry `message`; its OAuth provider sends `error_description`
const ProviderErrorBody = Schema.Struct({
  message: Schema.optionalKey(Schema.String),
  error_description: Schema.optionalKey(Schema.String),
});

const describe = Schema.decodeUnknownOption(ProviderErrorBody);

const sentence = (cause: APIError) =>
  Option.getOrElse(
    Option.flatMap(describe(cause.body), (body) =>
      Option.fromNullishOr(body.message ?? body.error_description)
    ),
    () => "Request could not be completed"
  );

/** The issuer's environment is invalid; `message` names the variable and what it must hold. */
export class InvalidSettings extends Data.TaggedError("InvalidSettings")<{
  readonly message: string;
}> {}

/** The database schema differs from the provider's in a way migration cannot repair. */
export class SchemaRepairRequired extends Data.TaggedError(
  "SchemaRepairRequired"
)<{ readonly message: string }> {}

export const refusal = (message: string) => new ProviderRefused({ message });

export const unavailability = (message: string) =>
  new ServiceUnavailable({ message });

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
  meanings: ProviderMeanings<Refused, Missing, Conflict, Unavailable> = {}
): Effect.Effect<
  A,
  InternalServerError | Refused | Missing | Conflict | Unavailable
> =>
  Effect.tryPromise({
    try: operation,
    catch: (cause) => {
      if (!isAPIError(cause)) {
        return InternalServerError.of(cause);
      }

      const status = cause.statusCode;

      let meaning:
        | ((message: string) => Refused | Missing | Conflict | Unavailable)
        | undefined;

      if (status === 400 || status === 422) {
        meaning = meanings.refused;
      } else if (status === 404) {
        meaning = meanings.missing;
      } else if (status === 409) {
        meaning = meanings.conflict;
      } else if (status === 503) {
        meaning = meanings.unavailable;
      }

      return meaning ? meaning(sentence(cause)) : InternalServerError.of(cause);
    },
  });

export const invalidInput = (path: Action.Issue["path"], message: string) =>
  new Action.InvalidInput({ message, issues: [{ path, message }] });

const isIssuerError = Schema.is(Schema.Union(errors));

const isRequestParseError = Predicate.isTagged("RequestParseError");

const routeError = (cause: unknown): IssuerError => {
  if (isIssuerError(cause)) {
    return cause;
  }

  if (
    HttpServerError.isHttpServerError(cause) &&
    isRequestParseError(cause.reason)
  ) {
    return new UnreadableRequest({ message: "Request body could not be read" });
  }

  return InternalServerError.of(cause);
};

const statuses = new Map<unknown, number>(
  errors.map(
    (schema) =>
      [
        schema,
        SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500,
      ] as const
  )
);

const encodeResponse = HttpServerResponse.schemaJson(Schema.Union(errors));

export const respond = (cause: unknown) => {
  const error = routeError(cause);
  const schema = errors.find((candidate) => Schema.is(candidate)(error));

  return encodeResponse(error, { status: statuses.get(schema) ?? 500 }).pipe(
    Effect.orDie
  );
};
