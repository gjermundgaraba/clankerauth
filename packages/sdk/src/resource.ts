import { Context, Effect, Result } from "effect";
import type * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import {
  admissionErrors,
  ConfigurationError,
  describeError,
  Forbidden,
  InsufficientScope,
  RateLimited,
  Unauthorized,
} from "./errors.ts";
import type { AdmissionError } from "./errors.ts";
import * as Verifier from "./verify.ts";

const describe = describeError(admissionErrors);

export class CurrentPrincipal extends Context.Service<CurrentPrincipal, Verifier.Principal>()(
  "@clankerauth/CurrentPrincipal",
) {}

export interface Options extends Verifier.Options {
  readonly scopes: readonly string[];
  /**
   * The scope a write needs beyond `requiredScopes`. Omit for a single-scope
   * resource, where verification alone is the whole policy and `authorize` passes
   * every action.
   */
  readonly writeScope?: string;
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

/** One resource: its verifier, discovery, scope policy and refusals. Acquire once per audience. */
export const make = Effect.fn("Resource.make")(function* (options: Options) {
  // An MCP client sends `new URL(metadata.resource).href`, and the token's audience is
  // that string. Refuse an identifier that is not already in that form, rather than
  // normalizing it and leaving the issuer's registered resource to disagree: an origin
  // root is `https://app.example/`, with the trailing slash.
  yield* Effect.try({
    try: () => new URL(options.resource),
    catch: () => new ConfigurationError({ message: "Resource identifier is not a URL" }),
  }).pipe(
    Effect.filterOrFail(
      (url) => url.href === options.resource,
      () =>
        new ConfigurationError({
          message: `Resource identifier must be canonical: use ${new URL(options.resource).href}`,
        }),
    ),
  );

  const discovery = yield* Effect.try({
    try: () =>
      Authentication.protectedResource({
        resource: options.resource,
        authorizationServers: [options.issuer],
        scopesSupported: options.scopes,
      }),
    catch: () => new ConfigurationError({ message: "Invalid resource metadata configuration" }),
  });

  const verifier = yield* Verifier.make(options);

  const scope = options.requiredScopes?.length ? options.requiredScopes.join(" ") : undefined;

  const challengeValue = (error?: "invalid_token" | "insufficient_scope", missing?: string) =>
    discovery.challenge({ error, scope: missing ?? scope });

  /** Bearer challenge for this resource; no error code when the request carried no credentials. */
  const challenge = (error?: "invalid_token" | "insufficient_scope") => ({
    "www-authenticate": challengeValue(error),
  });

  /**
   * The one header besides the content type that a refusal carries: an RFC 6750
   * challenge naming only the missing scope, or an RFC 6585 retry hint.
   */
  const refusalHeader = (
    error: AdmissionError,
    credential: boolean,
  ): readonly [string, string] | undefined => {
    if (error instanceof RateLimited) return ["retry-after", "60"];

    if (error instanceof InsufficientScope)
      return ["www-authenticate", challengeValue("insufficient_scope", error.scope)];

    if (error instanceof Forbidden)
      return ["www-authenticate", challengeValue("insufficient_scope")];

    // RFC 6750 §3.1: a request that carried no credentials gets no error code.
    if (error instanceof Unauthorized)
      return ["www-authenticate", credential ? challengeValue("invalid_token") : challengeValue()];

    return undefined;
  };

  const asRecord = (header: readonly [string, string] | undefined) =>
    header === undefined ? {} : { [header[0]]: header[1] };

  /** The header a caller rendering its own response adds for this failure. */
  const headers = (error: AdmissionError) => asRecord(refusalHeader(error, true));

  /** The write scope, if one is configured and this principal lacks it. */
  const missingScope = (principal: Verifier.Principal) =>
    options.writeScope !== undefined && !principal.scopes.includes(options.writeScope)
      ? options.writeScope
      : undefined;

  const refuse = (error: AdmissionError, authorization: string | null | undefined) =>
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

  /**
   * Verify one Authorization header value outside an Effect router: a Node `upgrade`
   * handler, a socket, a per-request endpoint. `access: "write"` also demands the
   * configured write scope, so a socket can require it before it is established.
   */
  const admit = Effect.fn("Resource.admit")(function* (
    authorization: string | null | undefined,
    access: Action.Access = "read",
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
   * The effect-actions pre-handler hook. A read needs nothing beyond what verification
   * already required; a write needs the configured write scope. Without one it passes,
   * so a single-scope resource has no authorization code at all.
   */
  const authorize = (
    action: Action.Any,
  ): Effect.Effect<void, InsufficientScope, CurrentPrincipal> =>
    action.access === "read" || options.writeScope === undefined
      ? Effect.void
      : Effect.flatMap(CurrentPrincipal, (principal) => {
          const missing = missingScope(principal);

          return missing === undefined
            ? Effect.void
            : Effect.fail(new InsufficientScope({ scope: missing }));
        });

  return {
    verifier,
    discovery,
    challenge,
    headers,
    admit,
    authorize,
    resource: options.resource,
    issuer: options.issuer,
    writeScope: options.writeScope,
  };
});

export type Resource = Effect.Success<ReturnType<typeof make>>;

/** Bearer authentication providing `CurrentPrincipal`, on the same admission `admit` renders. */
export const middleware = (resource: Resource) =>
  Authentication.middleware(
    CurrentPrincipal,
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const admission = yield* resource.admit(request.headers.authorization);

      if (admission.ok) return admission.principal;

      return yield* Effect.fail(
        HttpServerResponse.text(admission.refusal.body, {
          status: admission.refusal.status,
          headers: admission.refusal.headers,
        }),
      );
    }),
  );
