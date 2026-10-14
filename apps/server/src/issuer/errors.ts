import { Data, Effect, Option, Predicate, Schema, SchemaAST } from "effect";
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

export class ProviderFailure extends Data.TaggedError("ProviderFailure")<{
  readonly status: number;
  readonly message: string;
  readonly cause: APIError;
}> {}

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

export const provider = <A>(operation: () => Promise<A>) =>
  Effect.tryPromise({
    try: operation,
    catch: (cause) =>
      isAPIError(cause)
        ? new ProviderFailure({ status: cause.statusCode, message: sentence(cause), cause })
        : InternalServerError.of(cause),
  });

const isProviderFailure = (cause: unknown): cause is ProviderFailure =>
  cause instanceof ProviderFailure;

const isRefusal = (failure: ProviderFailure) => failure.status === 400 || failure.status === 422;

export const refused = <A, E, R>(effect: Effect.Effect<A, E | ProviderFailure, R>) =>
  Effect.catchIf(effect, isProviderFailure, (failure) =>
    Effect.fail(
      isRefusal(failure)
        ? new ProviderRefused({ message: failure.message })
        : InternalServerError.of(failure),
    ),
  );

export const refusedOrMissing =
  <N>(notFound: () => N) =>
  <A, E, R>(effect: Effect.Effect<A, E | ProviderFailure, R>) =>
    Effect.catchIf(effect, isProviderFailure, (failure) =>
      Effect.fail(
        failure.status === 404
          ? notFound()
          : isRefusal(failure)
            ? new ProviderRefused({ message: failure.message })
            : InternalServerError.of(failure),
      ),
    );

export const missing =
  <N>(notFound: () => N) =>
  <A, E, R>(effect: Effect.Effect<A, E | ProviderFailure, R>) =>
    Effect.catchIf(effect, isProviderFailure, (failure) =>
      Effect.fail(failure.status === 404 ? notFound() : InternalServerError.of(failure)),
    );

export const internal = <A, E, R>(effect: Effect.Effect<A, E | ProviderFailure, R>) =>
  Effect.catchIf(effect, isProviderFailure, (failure) =>
    Effect.fail(InternalServerError.of(failure)),
  );

export const undecided = <A, E, R>(effect: Effect.Effect<A, E | ProviderFailure, R>) =>
  Effect.catchIf(effect, isProviderFailure, (failure) =>
    Effect.fail(
      failure.status === 503
        ? new ServiceUnavailable({ message: failure.message })
        : InternalServerError.of(failure),
    ),
  );

export const invalidInput = (path: Action.Issue["path"], message: string) =>
  new Action.InvalidInput({ message, issues: [{ path, message }] });

type RouteError = IssuerError | Action.Forbidden;

const routeErrors = [...errors, Action.Forbidden] as const;

const statuses = new Map<unknown, number>(
  routeErrors.map(
    (schema) => [schema, SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500] as const,
  ),
);

const isRouteError = (cause: unknown): cause is RouteError =>
  routeErrors.some((schema) => Schema.is(schema)(cause));

const isRequestParseError = Predicate.isTagged("RequestParseError");

const routeError = (cause: unknown): RouteError => {
  if (isRouteError(cause)) return cause;

  if (cause instanceof ProviderFailure) {
    if (isRefusal(cause)) return new ProviderRefused({ message: cause.message });

    if (cause.status === 401 || cause.status === 403)
      return new Action.Forbidden({ message: cause.message });

    if (cause.status === 503) return new ServiceUnavailable({ message: cause.message });
  }

  if (HttpServerError.isHttpServerError(cause) && isRequestParseError(cause.reason))
    return new UnreadableRequest({ message: "Request body could not be read" });

  return InternalServerError.of(cause);
};

const encodeResponse = HttpServerResponse.schemaJson(Schema.Union(routeErrors));

export const respond = (cause: unknown) => {
  const error = routeError(cause);
  const schema = routeErrors.find((candidate) => Schema.is(candidate)(error));

  return encodeResponse(error, { status: statuses.get(schema) ?? 500 }).pipe(Effect.orDie);
};
