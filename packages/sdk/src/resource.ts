import { Clock, Context, Duration, Effect, Layer, Option, Redacted, Ref, Result } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http";
import type { HttpClient } from "effect/http";
import type { HttpApiSecurity } from "effect/http-api";
import type { ConfigurationError } from "./errors.ts";
import { InsufficientScope, ProviderUnavailable, Unauthorized } from "./errors.ts";
import type { AuthenticationError } from "./errors.ts";
import { keyListRefresh } from "./refresh.ts";
import { CurrentPrincipal, Whoami } from "./session.ts";
import type { Caller } from "./session.ts";
import * as Verifier from "./verify.ts";

/**
 * What a caller lacking `scope` is refused with, wherever the lack is found. Only an OAuth
 * client can step up, so only its `Forbidden` names the scope: an API key or the process
 * cannot re-authorize.
 */
const forbidden = (scope: string, actor: Caller["actor"]) => {
  const message = `Requires ${scope}.`;

  return actor.kind === "client"
    ? new Action.Forbidden({ message, scopes: [scope] })
    : new Action.Forbidden({ message });
};

/**
 * The one scope check, which `requires`, `admitted`, `admit` and `watch` share: what
 * `principal` is refused for lacking `scope`, if one is asked for and it lacks it.
 */
const lacking = (principal: Caller, scope: string | undefined) =>
  scope === undefined || principal.scopes.includes(scope)
    ? undefined
    : forbidden(scope, principal.actor);

/**
 * A verification failure as every effect-actions surface declares it: the built-in
 * `Unauthenticated` and `Forbidden`, which every client decodes. The issuer being
 * unreachable stays the SDK's own `ProviderUnavailable`, which the descriptor declares.
 */
const refusalOf = (error: AuthenticationError): Action.Refusal | ProviderUnavailable => {
  if (error instanceof Unauthorized) return new Action.Unauthenticated({ message: error.message });

  if (error instanceof InsufficientScope) return forbidden(error.scope, error.actor);

  return error;
};

/**
 * Verify a request's bearer token with `verifier`, failing as an effect-actions surface
 * refuses: what a verifier of your own, given to `Authentication.layer`, yields before its
 * own checks. A declared resource's `provider` does this; reach for it only with a verifier
 * of your own, whose descriptor declares `ProviderUnavailable` too, or another error the
 * verifier maps it to.
 */
export const authenticate = (
  verifier: Verifier.Verifier,
  token: Redacted.Redacted<string>,
): Effect.Effect<Verifier.Principal, Action.Refusal | ProviderUnavailable> =>
  Effect.mapError(verifier.verifyToken(Redacted.value(token)), refusalOf);

export interface Options {
  readonly issuer: string;
  /**
   * The origin browsers and agents reach this application at: the listener that publishes
   * discovery. The resource is its origin root, so any path here is discarded: one identifier
   * covers `/api`, `/mcp` and sockets. A request reaching that listener at another host is
   * logged once as a warning, since an OAuth client discovering the resource there refuses it.
   */
  readonly publicUrl: URL;
  /** `false` refuses API keys without reading the issuer's key list; only OAuth access tokens are accepted. */
  readonly apiKeys?: boolean;
  /**
   * `false` publishes no RFC 9728 discovery and names none in a challenge: for a surface
   * whose callers hold API keys and never run an OAuth flow, such as a second listener
   * beside the one that publishes the resource. That listener still names the same resource,
   * so it takes the publishing listener's `publicUrl`, not its own.
   */
  readonly discovery?: boolean;
}

/**
 * A refusal a caller outside the router can send as-is: the status, headers and JSON body
 * `authentication` answers the same refusal with on a route.
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

const build = Effect.fn("Resource.layer")(function* <Scope extends string>(
  authentication: Authentication.Any,
  { scopes, required }: Declaration<Scope>,
  options: Options,
) {
  // One resource per application, at the public origin root, trailing slash and all.
  // An MCP client sends `new URL(metadata.resource).href`, and the token's audience is
  // that string, so deriving it here is what keeps the two in agreement.
  const identifier = new URL("/", options.publicUrl).href;

  // effect-actions checks every scope here is an OAuth scope token, when the provider builds.
  const metadata = {
    resource: identifier,
    authorizationServers: [options.issuer],
    scopesSupported: scopes,
    scopesRequired: [required],
  } satisfies Authentication.ProtectedResource;

  const protectedResource = options.discovery === false ? undefined : metadata;

  const unbounded = yield* Verifier.make({
    issuer: options.issuer,
    resource: identifier,
    requiredScopes: [required],
    apiKeys: options.apiKeys,
  });

  // A request must not wait on an issuer that does not answer: the credential is refused
  // as unavailable, and a read no other request waits on is interrupted. A key list read
  // gives up sooner, so a held list still decides a key.
  const deadline = <A, E>(effect: Effect.Effect<A, E>) =>
    Effect.timeoutOrElse(effect, {
      duration: "5 seconds",
      orElse: () => Effect.fail(new ProviderUnavailable({ operation: "verify.timeout" })),
    });

  const verifier: Verifier.Verifier = {
    verifyToken: (token) => deadline(unbounded.verifyToken(token)),
  };

  /**
   * The principal an Authorization header value proves, holding `scope` if one is asked
   * for, or what a route refuses the same request with: `admit` renders it, `watch` fails
   * with it.
   */
  const principalOf = Effect.fn("Resource.principal")(function* (
    authorization: string | null | undefined,
    scope: string | undefined,
  ) {
    const token = Authentication.bearerTokenOf(authorization);

    // As a protected route refuses a request without one, before its verifier runs.
    if (Option.isNone(token))
      return yield* new Action.Unauthenticated({ message: "A bearer token is required." });

    const principal = yield* authenticate(verifier, token.value);
    const refusal = lacking(principal, scope);

    return refusal === undefined ? principal : yield* refusal;
  });

  /**
   * Verify one Authorization header value outside an Effect router: a Node `upgrade`
   * handler, a socket, a per-request endpoint. With `scope`, the credential must also hold
   * it, so a socket that writes demands its scope before it is established. It is
   * `admitted`'s check, given the header rather than the request.
   */
  const admit = Effect.fn("Resource.admit")(function* (
    authorization: string | null | undefined,
    scope?: Scope,
  ) {
    const verified = yield* Effect.result(principalOf(authorization, scope));

    if (Result.isSuccess(verified))
      return { ok: true, principal: verified.success } satisfies Admission;

    // A refusal, or the `ProviderUnavailable` the descriptor declares, as its routes send it.
    const web = HttpServerResponse.toWeb(
      Authentication.refusalResponse(verified.failure, {
        authentication,
        protectedResource,
        authorization,
      }),
    );

    return {
      ok: false,
      refusal: {
        status: web.status,
        headers: Object.fromEntries(web.headers),
        body: yield* Effect.promise(() => web.text()),
      },
    } satisfies Admission;
  });

  /**
   * Hold what `admit` let in, such as a socket, to the same header value and `scope`: fails
   * with the refusal `admit` would now answer, once a token expires or a key is revoked,
   * expires or loses the scope. Never succeeds; race it against the connection.
   */
  const watch = (authorization: string | null | undefined, scope?: Scope) =>
    Effect.forever(
      Effect.gen(function* () {
        const principal = yield* principalOf(authorization, scope);
        const now = yield* Clock.currentTimeMillis;
        const remaining = Math.max(0, (principal.expiresAt ?? Infinity) - now);

        // A key is checked again against each refreshed list, until it expires.
        if (principal.actor.kind === "key")
          return yield* Effect.sleep(Math.min(remaining, Duration.toMillis(keyListRefresh)));

        // An access token cannot be revoked and never becomes valid again, so its expiry is
        // all that ends it: no second JWKS read that an issuer outage could fail. It ends as
        // the verifier refuses an expired token.
        yield* Effect.sleep(remaining);

        return yield* refusalOf(new Unauthorized());
      }),
    );

  return {
    /** The resource identifier: the public origin root, which a token's audience names. */
    resource: identifier,
    issuer: options.issuer,
    /** What `authentication` publishes and names in every challenge; none with `discovery: false`. */
    protectedResource,
    verifier,
    admit,
    watch,
  } satisfies Built<Scope>;
});

/**
 * What a declared resource's `layer` builds: its verifier and its refusals. An
 * interface, as `Declared` is, so a consumer's emitted declarations name it. `Scope` is the
 * resource's scopes, as `make` infers them: a scope `admit` and `watch` check is one of them.
 */
export interface Built<Scope extends string = string> {
  /** The resource identifier: the public origin root, which a token's audience names. */
  readonly resource: string;
  readonly issuer: string;
  /** What `authentication` publishes and names in every challenge; none with `discovery: false`. */
  readonly protectedResource: Authentication.ProtectedResource | undefined;
  readonly verifier: Verifier.Verifier;
  /**
   * What an Authorization header value amounts to, for a caller outside the router: any
   * verified caller, or with `scope`, one that also holds it.
   */
  readonly admit: (
    authorization: string | null | undefined,
    scope?: Scope,
  ) => Effect.Effect<Admission>;
  /** Fails, with the refusal `admit` would now answer, once the credential it admitted stops being valid. */
  readonly watch: (
    authorization: string | null | undefined,
    scope?: Scope,
  ) => Effect.Effect<never, Action.Refusal | ProviderUnavailable>;
}

/**
 * The service identity of the resource whose descriptor is named `Name`, so two resources are
 * two services: each surface reads its own, whatever layer graph builds them.
 */
export interface Resource<Name extends string> {
  readonly "~@clankerauth/Resource": Name;
}

/** What `make` requires a descriptor to declare: the issuer being unreachable. */
type Unavailable = readonly [typeof ProviderUnavailable];

/**
 * A descriptor of `CurrentPrincipal` by bearer token, declaring `ProviderUnavailable`, as a
 * binding and an MCP endpoint name it, beside the contracts:
 * `Authentication.make("notes.Login", CurrentPrincipal, { error: ProviderUnavailable })`.
 * `E` is what it declares, that one error unless it declares more.
 */
export type Login<
  Name extends string = string,
  E extends Action.Errors = Unavailable,
> = Authentication.Descriptor<CurrentPrincipal, Caller, HttpApiSecurity.Http, Name, E>;

/**
 * `unknown` when every alternative of `E` declares `ProviderUnavailable`, by what its schemas
 * decode (one of them, or a `Schema.Union` holding it), and what names the omission otherwise:
 * a descriptor that may declare it, such as `error: cond ? ProviderUnavailable : undefined`,
 * does not.
 */
type DeclaresUnavailable<E extends Action.Errors> = [
  E extends unknown ? (ProviderUnavailable extends E[number]["Type"] ? never : E) : never,
] extends [never]
  ? unknown
  : { readonly "Resource.make takes a descriptor declaring error: ProviderUnavailable": never };

/**
 * What a resource declares beside its descriptor, the same in every deployment: the
 * application's scopes, and the one every credential must carry.
 */
export interface Declaration<Scope extends string = string> {
  /**
   * Every scope the resource has: published in discovery, and held by `local`'s principal.
   * effect-actions refuses one that is no OAuth scope token when the provider builds that
   * discovery; with `discovery: false`, nothing checks them.
   */
  readonly scopes: readonly Scope[];
  /**
   * The scope every credential must carry, one of `scopes`: verification requires it, every
   * 401 names it, and a first login requests it. Any other scope is the application's to
   * require, with `requires`.
   */
  readonly required: NoInfer<Scope>;
}

/**
 * A declared resource, as `make` gives it. `E` is what its descriptor declares,
 * `ProviderUnavailable` alone unless it declares more. `Scope` is its scopes, as `make`
 * infers them: `requires`, `admitted`, `admit` and `watch` take only one of them, so a scope
 * it does not declare is a type error. Where an exported declaration must be written out,
 * annotate with all three:
 * `Resource.Declared<"notes.Login", readonly [typeof ProviderUnavailable], "notes:read" | "notes:write">`.
 */
export interface Declared<
  Name extends string,
  E extends Action.Errors = Unavailable,
  Scope extends string = string,
> {
  /** The descriptor the resource verifies, as given to `make`. */
  readonly authentication: Login<Name, E>;
  /** The built resource: `admit` and `watch` for a caller outside the router, `verifier`. */
  readonly service: Context.Service<Resource<Name>, Built<Scope>>;
  /** The resource, built once per layer graph: provide it beside the surfaces it guards. */
  readonly layer: (
    options: Options,
  ) => Layer.Layer<Resource<Name>, ConfigurationError, HttpClient.HttpClient>;
  /**
   * The descriptor's provider: its verifier, reading the resource, which also publishes the
   * resource's discovery. Provide it to every layer serving the resource's protected actions.
   */
  readonly provider: Layer.Layer<
    Authentication.Provider<CurrentPrincipal, Name>,
    never,
    Resource<Name> | HttpRouter.HttpRouter
  >;
  /** Refuses a caller without `scope`, for an authorizer the application writes. */
  readonly requires: (scope: Scope) => Effect.Effect<void, Action.Forbidden, CurrentPrincipal>;
  /** The host's own routes, admitted as the resource's actions are, holding `scope` if given. */
  readonly admitted: (scope?: Scope) => Authentication.Protection<CurrentPrincipal, Name>;
  /** The process itself as a principal, for a trusted local surface. */
  readonly local: (subject: string) => Caller;
  /** `Whoami`, answered from the verified credential. */
  readonly session: Action.Implementation<
    typeof Whoami,
    { readonly whoami: CurrentPrincipal },
    never,
    Resource<Name>
  >;
}

/**
 * Declare an application's resource, at module level, by the descriptor its bindings and
 * MCP endpoints name, its scopes and the one every credential carries:
 * `const Notes = Resource.make(Login, { scopes: ["notes:read", "notes:write"], required: "notes:read" })`.
 * The descriptor's name names its service, so two resources of one process are two services.
 * What varies by deployment comes later, where the application starts, as
 * `Notes.layer(options)`, provided once beside the surfaces. Which scope an action needs
 * beyond `required` is the application's rule, written with `requires`. The descriptor
 * declares `ProviderUnavailable`, which its verifier fails with when the issuer cannot be
 * reached; one that does not is a type error here.
 */
export const make = <
  const Name extends string,
  E extends Action.Errors,
  const Scope extends string,
>(
  authentication: Login<Name, E> & DeclaresUnavailable<E>,
  declaration: Declaration<Scope>,
): Declared<Name, E, Scope> => {
  const { scopes } = declaration;

  const service = Context.Service<Resource<Name>, Built<Scope>>(
    `@clankerauth/Resource/${authentication.name}`,
  );

  const layer = (options: Options) =>
    Layer.effect(service, build(authentication, declaration, options));

  // The descriptor as the verifier fails: `DeclaresUnavailable` holds that every alternative of
  // `E` declares `ProviderUnavailable`, which a generic `E` cannot show the types by itself.
  const declaring: Login<Name, E | Unavailable> = authentication;

  // The descriptor's verifier: a token to its principal, a refusal, or `ProviderUnavailable`.
  const provider = Authentication.layer(
    declaring,
    Effect.gen(function* () {
      const { verifier, resource, protectedResource } = yield* service;
      const host = new URL(resource).host;
      const warned = yield* Ref.make(protectedResource === undefined);

      // RFC 9728 has a client refuse metadata naming another resource than the one it
      // reached, so a listener publishing discovery at another host fails every OAuth login
      // while keys keep working. A proxy may rewrite the host, so this warns and refuses nothing.
      const noteHost = Effect.gen(function* () {
        if (yield* Ref.get(warned)) return;

        const reached = (yield* HttpServerRequest.HttpServerRequest).headers.host;

        if (reached === undefined || reached === host) return;

        yield* Ref.set(warned, true);
        yield* Effect.logWarning(
          `The resource ${resource} publishes discovery, but a request reached it at ${reached}: an OAuth client discovering it there refuses the mismatch. Set publicUrl to the origin this listener is reached at.`,
        );
      });

      return (token: Redacted.Redacted<string>) =>
        Effect.andThen(noteHost, authenticate(verifier, token));
    }),
    { protectedResource: Effect.map(service, ({ protectedResource }) => protectedResource) },
  );

  /**
   * Refuse a caller that lacks `scope`, as the application's authorizer decides:
   * `Action.implement(actions, handlers, { authorize: (action) => action.readOnly ? Effect.void : Notes.requires("notes:write") })`.
   * The `Forbidden` names the scope for an OAuth client, which steps up to it; an API key or
   * the process cannot, so theirs names none.
   */
  const requires = (scope: Scope): Effect.Effect<void, Action.Forbidden, CurrentPrincipal> =>
    Effect.flatMap(CurrentPrincipal, (principal) => {
      const refusal = lacking(principal, scope);

      return refusal === undefined ? Effect.void : Effect.fail(refusal);
    });

  /**
   * The host's own routes behind the resource, provided around them:
   * `HttpRouter.add("GET", "/frame", frame).pipe(Layer.provide(Notes.admitted().layer))`.
   * effect-actions' `Authentication.protect` authenticates them with the descriptor's provider,
   * as it does an action's route, and answers them as one; `scope`, if given, is checked
   * inside it with `requires`. An admitted route reads its caller from `CurrentPrincipal`.
   */
  const admitted = (scope?: Scope): Authentication.Protection<CurrentPrincipal, Name> =>
    scope === undefined
      ? Authentication.protect(authentication)
      : HttpRouter.middleware((route) => Effect.andThen(requires(scope), route)).combine(
          Authentication.protect(authentication),
        );

  /**
   * The process itself as the caller of a trusted local surface, such as stdio MCP or a local
   * command, where no credential exists to verify: every scope the resource declares, no
   * expiry. The application's authorizer runs against it as against a verified caller.
   * `Effect.provideService(CurrentPrincipal, Notes.local("owner"))`.
   */
  const local = (subject: string): Caller => ({
    subject,
    scopes: [...scopes],
    actor: { kind: "local" },
    expiresAt: undefined,
  });

  /**
   * `whoami` of `@gjermundgaraba/clankerauth-sdk/session`, already answered. The credential
   * is a transport concern: a process surface has none, so serve it over HTTP alone,
   * `ActionHttp.layer(Http, [app, Notes.session])`, and leave it out of MCP.
   */
  const session = Action.implement(
    Whoami,
    Effect.map(
      service,
      ({ issuer }) =>
        () =>
          Effect.map(CurrentPrincipal, (principal) => ({
            subject: principal.subject,
            issuer,
            scopes: principal.scopes,
          })),
    ),
    { authorize: Action.allowAll },
  );

  return {
    authentication,
    service,
    layer,
    provider,
    requires,
    admitted,
    local,
    session,
  };
};
