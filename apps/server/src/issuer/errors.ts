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

export class InvalidSettings extends Data.TaggedError("InvalidSettings")<{
  readonly message: string;
}> {}

export class SchemaRepairRequired extends Data.TaggedError(
  "SchemaRepairRequired"
)<{ readonly message: string }> {}

export const refusal = (message: string) => new ProviderRefused({ message });

export const unavailability = (message: string) =>
  new ServiceUnavailable({ message });

export interface ProviderMeanings<Refused, Missing, Conflict, Unavailable> {
  readonly refused?: (message: string) => Refused;
  readonly missing?: (message: string) => Missing;
  readonly conflict?: (message: string) => Conflict;
  readonly unavailable?: (message: string) => Unavailable;
}

const meaningByStatus = new Map<
  number,
  keyof ProviderMeanings<unknown, unknown, unknown, unknown>
>([
  [400, "refused"],
  [422, "refused"],
  [404, "missing"],
  [409, "conflict"],
  [503, "unavailable"],
]);

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

      const kind = meaningByStatus.get(cause.statusCode);
      const meaning = kind === undefined ? undefined : meanings[kind];

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
