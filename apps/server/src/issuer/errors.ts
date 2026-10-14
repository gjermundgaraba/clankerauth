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

/** A provider API call that answered with an error status. Its caller names what it means. */
export class ProviderFailure extends Data.TaggedError("ProviderFailure")<{
  readonly status: number;
  readonly message: string;
  readonly cause: APIError;
}> {}

// Better Auth core errors carry `message`; the OAuth provider uses `error_description`.
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

/** Provider SDK calls. A refusal keeps its status for the caller; anything else is the issuer's. */
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

/** A provider refusal of the input, or else the issuer's own fault. */
export const refused = <A, E, R>(effect: Effect.Effect<A, E | ProviderFailure, R>) =>
  Effect.catchIf(effect, isProviderFailure, (failure) =>
    Effect.fail(
      isRefusal(failure)
        ? new ProviderRefused({ message: failure.message })
        : InternalServerError.of(failure),
    ),
  );

/** As `refused`, with a provider 404 named by `notFound`. */
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

/** A provider 404 named by `notFound`; anything else the issuer's own fault. */
export const missing =
  <N>(notFound: () => N) =>
  <A, E, R>(effect: Effect.Effect<A, E | ProviderFailure, R>) =>
    Effect.catchIf(effect, isProviderFailure, (failure) =>
      Effect.fail(failure.status === 404 ? notFound() : InternalServerError.of(failure)),
    );

/** Whatever the provider answered, the issuer's own fault. */
export const internal = <A, E, R>(effect: Effect.Effect<A, E | ProviderFailure, R>) =>
  Effect.catchIf(effect, isProviderFailure, (failure) =>
    Effect.fail(InternalServerError.of(failure)),
  );

/** A provider that cannot decide now, or else the issuer's own fault. */
export const undecided = <A, E, R>(effect: Effect.Effect<A, E | ProviderFailure, R>) =>
  Effect.catchIf(effect, isProviderFailure, (failure) =>
    Effect.fail(
      failure.status === 503
        ? new ServiceUnavailable({ message: failure.message })
        : InternalServerError.of(failure),
    ),
  );

/**
 * Input that decodes but cannot be served: effect-actions' built-in 400, which every endpoint
 * and tool declares, naming the field at fault.
 */
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

/**
 * What a route that is not an action answers a failure with: forward auth, the provider
 * bridge and `/healthz`. A provider 401 or 403 there refuses the operation.
 */
const routeError = (cause: unknown): RouteError => {
  if (isRouteError(cause)) return cause;

  if (cause instanceof ProviderFailure) {
    if (isRefusal(cause)) return new ProviderRefused({ message: cause.message });

    if (cause.status === 401 || cause.status === 403)
      return new Action.Forbidden({ message: cause.message });

    if (cause.status === 503) return new ServiceUnavailable({ message: cause.message });
  }

  // A request body this issuer could not read — truncated, oversized, an abandoned
  // upload — is the caller's, not a failure of its own.
  if (HttpServerError.isHttpServerError(cause) && isRequestParseError(cause.reason))
    return new UnreadableRequest({ message: "Request body could not be read" });

  return InternalServerError.of(cause);
};

const encodeResponse = HttpServerResponse.schemaJson(Schema.Union(routeErrors));

/** Translate whatever a route failed with, once, into its public response. */
export const respond = (cause: unknown) => {
  const error = routeError(cause);
  const schema = routeErrors.find((candidate) => Schema.is(candidate)(error));

  return encodeResponse(error, { status: statuses.get(schema) ?? 500 }).pipe(Effect.orDie);
};
