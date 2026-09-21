import { Context, Effect, Result, Schema, SchemaAST } from "effect";
import type * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import {
  authenticationErrors,
  ConfigurationError,
  InsufficientScope,
  RateLimited,
  Unauthorized,
} from "./errors.ts";
import type { AuthenticationError } from "./errors.ts";
import { Session } from "./session.ts";
import * as Verifier from "./verify.ts";

const encoders = new Map(
  authenticationErrors.map((schema) => [
    schema,
    {
      status: SchemaAST.resolveAt<number>("httpApiStatus")(schema.ast) ?? 500,
      encode: Schema.encodeUnknownEffect(Schema.toCodecJson(schema)),
    },
  ]),
);

/** One refusal as its own status and JSON body. An undeclared error is a defect. */
const describe = (error: AuthenticationError) => {
  const schema = authenticationErrors.find((candidate) => Schema.is(candidate)(error));
  const encoder = schema === undefined ? undefined : encoders.get(schema);

  if (encoder === undefined) return Effect.die(new Error("Undeclared error"));

  return Effect.map(Effect.orDie(encoder.encode(error)), (body) => ({
    status: encoder.status,
    body: JSON.stringify(body),
  }));
};

export class CurrentPrincipal extends Context.Service<CurrentPrincipal, Verifier.Principal>()(
  "@clankerauth/CurrentPrincipal",
) {}

/** What this resource's credentials must carry. */
export interface Scopes {
  /** Required of every credential, so verification alone admits a read. */
  readonly read: string;
  /**
   * Additionally required by an `access: "write"` action and by `admit(..., "write")`.
   * Omit for a single-scope application, where verification is the whole policy.
   */
  readonly write?: string;
}

export interface Options {
  readonly issuer: string;
  /**
   * The origin browsers and agents reach this application at. The resource is its origin
   * root, so any path here is discarded: one identifier covers `/api`, `/mcp` and sockets.
   */
  readonly publicUrl: URL;
  readonly scopes: Scopes;
  /** `false` rejects API keys without consulting the issuer; only OAuth access tokens are accepted. */
  readonly apiKeys?: boolean;
}

/**
 * A refusal a caller outside the router can send as-is: an RFC 6750 challenge or a
 * `Retry-After`, `Cache-Control: no-store`, and the error's own JSON encoding.
 */
export interface Refusal {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

/** What one Authorization header value amounts to for this resource. */
export type Admission =
  | { readonly ok: true; readonly principal: Verifier.Principal }
  | { readonly ok: false; readonly refusal: Refusal };

/** One resource: its verifier, discovery, scope policy and refusals. Acquire once per application. */
export const make = Effect.fn("Resource.make")(function* (options: Options) {
  // One resource per application, at the public origin root, trailing slash and all.
  // An MCP client sends `new URL(metadata.resource).href`, and the token's audience is
  // that string, so deriving it here is what keeps the two in agreement.
  const identifier = new URL("/", options.publicUrl).href;

  const scopesSupported =
    options.scopes.write === undefined
      ? [options.scopes.read]
      : [options.scopes.read, options.scopes.write];

  const discovery = yield* Effect.try({
    try: () =>
      Authentication.protectedResource({
        resource: identifier,
        authorizationServers: [options.issuer],
        scopesSupported,
      }),
    catch: () => new ConfigurationError({ message: "Invalid resource metadata configuration" }),
  });

  const verifier = yield* Verifier.make({
    issuer: options.issuer,
    resource: identifier,
    requiredScopes: [options.scopes.read],
    apiKeys: options.apiKeys,
  });

  const challengeValue = (error?: "invalid_token" | "insufficient_scope", missing?: string) =>
    discovery.challenge({ error, scope: missing ?? options.scopes.read });

  /**
   * The one header besides the content type that a refusal carries: an RFC 6750
   * challenge naming only the missing scope, or an RFC 6585 retry hint.
   */
  const refusalHeader = (
    error: AuthenticationError,
    credential: boolean,
  ): readonly [string, string] | undefined => {
    if (error instanceof RateLimited) return ["retry-after", "60"];

    if (error instanceof InsufficientScope)
      return ["www-authenticate", challengeValue("insufficient_scope", error.scope)];

    // RFC 6750 §3.1: a request that carried no credentials gets no error code.
    if (error instanceof Unauthorized)
      return ["www-authenticate", credential ? challengeValue("invalid_token") : challengeValue()];

    return undefined;
  };

  const asRecord = (header: readonly [string, string] | undefined) =>
    header === undefined ? {} : { [header[0]]: header[1] };

  const refuse = (error: AuthenticationError, authorization: string | null | undefined) =>
    Effect.map(describe(error), ({ status, body }): Admission => ({
      ok: false,
      refusal: {
        status,
        headers: {
          ...asRecord(refusalHeader(error, authorization !== undefined && authorization !== null)),
          "content-type": "application/json",
          "cache-control": "no-store",
        },
        body,
      },
    }));

  /** The write scope, if one is configured and this principal lacks it. */
  const missingScope = (principal: Verifier.Principal) =>
    options.scopes.write !== undefined && !principal.scopes.includes(options.scopes.write)
      ? options.scopes.write
      : undefined;

  /**
   * Verify one Authorization header value outside an Effect router: a Node `upgrade`
   * handler, a socket, a per-request endpoint. `access` is the same declaration an
   * action carries, so `"write"` demands the write scope before a socket is established.
   */
  const admit = Effect.fn("Resource.admit")(function* (
    authorization: string | null | undefined,
    access: Action.Access,
  ) {
    const verified = yield* Effect.result(verifier.verify(authorization));

    if (Result.isFailure(verified)) return yield* refuse(verified.failure, authorization);
    const principal = verified.success;
    const missing = access === "write" ? missingScope(principal) : undefined;

    if (missing !== undefined)
      return yield* refuse(new InsufficientScope({ scope: missing }), authorization);

    return { ok: true, principal } satisfies Admission;
  });

  /**
   * The effect-actions pre-handler hook, bound once per surface. A read needs nothing
   * beyond what verification already required; a write needs the configured write scope.
   * Without one it passes, so a single-scope resource has no authorization code at all.
   */
  const authorize = (
    action: Action.Any,
  ): Effect.Effect<void, InsufficientScope, CurrentPrincipal> =>
    action.access === "read" || options.scopes.write === undefined
      ? Effect.void
      : Effect.flatMap(CurrentPrincipal, (principal) => {
          const missing = missingScope(principal);

          return missing === undefined
            ? Effect.void
            : Effect.fail(new InsufficientScope({ scope: missing }));
        });

  /** The `session` group of `@gjermundgaraba/clankerauth-sdk/session`, already answered. */
  const session = Session.implement({
    whoami: () =>
      Effect.map(CurrentPrincipal, ({ subject, scopes }) => ({
        subject,
        issuer: options.issuer,
        scopes,
      })),
  });

  return {
    verifier,
    discovery,
    admit,
    authorize,
    session,
    resource: identifier,
    issuer: options.issuer,
    publicUrl: options.publicUrl,
    scopes: options.scopes,
  };
});

export type Resource = Effect.Success<ReturnType<typeof make>>;

/** Bearer authentication providing `CurrentPrincipal`, on the same admission `admit` renders. */
export const middleware = (resource: Resource) =>
  Authentication.middleware(
    CurrentPrincipal,
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      // Read level: an action's own `access` is what the authorization hook then enforces.
      const admission = yield* resource.admit(request.headers.authorization, "read");

      if (admission.ok) return admission.principal;

      return yield* Effect.fail(
        HttpServerResponse.text(admission.refusal.body, {
          status: admission.refusal.status,
          headers: admission.refusal.headers,
        }),
      );
    }),
  );
