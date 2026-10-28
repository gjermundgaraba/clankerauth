import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import {
  Clock,
  Context,
  Duration,
  Effect,
  Layer,
  Option,
  Redacted,
  Ref,
  Result,
} from "effect";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http";
import type { HttpClient } from "effect/http";
import type { HttpApiSecurity } from "effect/http-api";

import type { ConfigurationError, AuthenticationError } from "./errors.ts";
import {
  InsufficientScope,
  ProviderUnavailable,
  Unauthorized,
} from "./errors.ts";
import { revocationDelay } from "./refresh.ts";
import { CurrentPrincipal, Whoami } from "./session.ts";
import type { Caller } from "./session.ts";
import * as Verifier from "./verify.ts";

const forbidden = (scope: string, actor: Caller["actor"]) => {
  const message = `Requires ${scope}.`;

  return actor.kind === "client"
    ? new Action.Forbidden({ message, scopes: [scope] })
    : new Action.Forbidden({ message });
};

const lacking = (principal: Caller, scope: string | undefined) =>
  scope === undefined || principal.scopes.includes(scope)
    ? undefined
    : forbidden(scope, principal.actor);

const refusalOf = (
  error: AuthenticationError
): Action.Refusal | ProviderUnavailable => {
  if (error instanceof Unauthorized) {
    return new Action.Unauthenticated({ message: error.message });
  }

  if (error instanceof InsufficientScope) {
    return forbidden(error.scope, error.actor);
  }

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
  token: Redacted.Redacted
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
  /**
   * What the resource's verifier keeps of what it reads, `Verifier.store()`: made once where
   * the process starts, so it outlives a layer built per request.
   */
  readonly store: Verifier.Store;
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

export const verificationDeadline = Duration.seconds(5);

const deadline = <A, E>(effect: Effect.Effect<A, E>) =>
  Effect.timeoutOrElse(effect, {
    duration: verificationDeadline,
    orElse: () =>
      Effect.fail(new ProviderUnavailable({ operation: "verify.timeout" })),
  });

/** What one Authorization header value amounts to for this resource. */
export type Admission =
  | { readonly ok: true; readonly principal: Verifier.Principal }
  | { readonly ok: false; readonly refusal: Refusal };

const build = Effect.fn("Resource.layer")(function* <Scope extends string>(
  authentication: Authentication.Any,
  { scopes, required }: Declaration<Scope>,
  options: Options
) {
  const identifier = new URL("/", options.publicUrl).href;

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
    store: options.store,
    requiredScopes: [required],
    apiKeys: options.apiKeys,
  });

  const verifier: Verifier.Verifier = {
    verifyToken: (token) => deadline(unbounded.verifyToken(token)),
  };

  const principalOf = Effect.fn("Resource.principal")(function* (
    authorization: string | null | undefined,
    scope: string | undefined
  ) {
    const token = Authentication.bearerTokenOf(authorization);

    if (Option.isNone(token)) {
      return yield* new Action.Unauthenticated({
        message: "A bearer token is required.",
      });
    }

    const principal = yield* authenticate(verifier, token.value);
    const refusal = lacking(principal, scope);

    return refusal === undefined ? principal : yield* refusal;
  });

  const admit = Effect.fn("Resource.admit")(function* (
    authorization: string | null | undefined,
    scope?: Scope
  ) {
    const verified = yield* Effect.result(principalOf(authorization, scope));

    if (Result.isSuccess(verified)) {
      return { ok: true, principal: verified.success } satisfies Admission;
    }

    const web = HttpServerResponse.toWeb(
      Authentication.refusalResponse(verified.failure, {
        authentication,
        protectedResource,
        authorization,
      })
    );

    return {
      ok: false,
      refusal: {
        status: web.status,
        headers: Object.fromEntries(web.headers),
        body: yield* Effect.promise(async () => await web.text()),
      },
    } satisfies Admission;
  });

  const watch = (authorization: string | null | undefined, scope?: Scope) =>
    Effect.forever(
      Effect.gen(function* () {
        const principal = yield* principalOf(authorization, scope);
        const now = yield* Clock.currentTimeMillis;
        const remaining = Math.max(0, (principal.expiresAt ?? Infinity) - now);

        if (principal.actor.kind === "key") {
          return yield* Effect.sleep(
            Math.min(remaining, Duration.toMillis(revocationDelay))
          );
        }

        yield* Effect.sleep(remaining);

        return yield* refusalOf(new Unauthorized());
      })
    );

  return {
    resource: identifier,
    issuer: options.issuer,
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
   * What an Authorization header value amounts to, for a caller outside the router, such as a
   * Node `upgrade` handler, a socket or a per-request endpoint: any verified caller, or with
   * `scope`, one that also holds it, so a socket that writes demands its scope before it is
   * established.
   */
  readonly admit: (
    authorization: string | null | undefined,
    scope?: Scope
  ) => Effect.Effect<Admission>;
  /**
   * Fails, with the refusal `admit` would now answer, once the credential it admitted stops
   * being valid: a token expires, or a key is revoked, expires or loses the scope. Never
   * succeeds; race it against the connection.
   */
  readonly watch: (
    authorization: string | null | undefined,
    scope?: Scope
  ) => Effect.Effect<never, Action.Refusal | ProviderUnavailable>;
}

/**
 * The service identity of the resource whose descriptor is named `Name`, so two resources are
 * two services: each surface reads its own, whatever layer graph builds them.
 */
export interface Resource<Name extends string> {
  readonly "~@clankerauth/Resource": Name;
}

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
> = Authentication.Descriptor<
  CurrentPrincipal,
  Caller,
  HttpApiSecurity.Http,
  Name,
  E
>;

type DeclaresUnavailable<E extends Action.Errors> = [
  E extends unknown
    ? ProviderUnavailable extends E[number]["Type"]
      ? never
      : E
    : never,
] extends [never]
  ? unknown
  : {
      readonly "Resource.make takes a descriptor declaring error: ProviderUnavailable": never;
    };

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
    options: Options
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
  /**
   * Refuses a caller without `scope`, for an authorizer the application writes:
   * `Action.implement(actions, handlers, { authorize: (action) => action.readOnly ? Effect.void : Notes.requires("notes:write") })`.
   * The `Forbidden` names the scope for an OAuth client, which steps up to it; an API key or
   * the process cannot, so theirs names none.
   */
  readonly requires: (
    scope: Scope
  ) => Effect.Effect<void, Action.Forbidden, CurrentPrincipal>;
  /**
   * The host's own routes, admitted as the resource's actions are, holding `scope` if given:
   * `HttpRouter.add("GET", "/frame", frame).pipe(Layer.provide(Notes.admitted().layer))`.
   * effect-actions' `Authentication.protect` authenticates them with the descriptor's provider
   * and answers them as it answers an action's route; `scope` is checked inside it with
   * `requires`. An admitted route reads its caller from `CurrentPrincipal`.
   */
  readonly admitted: (
    scope?: Scope
  ) => Authentication.Protection<CurrentPrincipal, Name>;
  /**
   * The process itself as a principal, for a trusted local surface such as stdio MCP or a
   * local command, where no credential exists to verify: every scope the resource declares,
   * no expiry. The application's authorizer runs against it as against a verified caller:
   * `Effect.provideService(CurrentPrincipal, Notes.local("owner"))`.
   */
  readonly local: (subject: string) => Caller;
  /**
   * `Whoami`, answered from the verified credential. A process surface has no credential, so
   * serve it over HTTP alone, `ActionHttp.layer(Http, [app, Notes.session])`, and leave it out
   * of MCP.
   */
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
  declaration: Declaration<Scope>
): Declared<Name, E, Scope> => {
  const { scopes } = declaration;

  const service = Context.Service<Resource<Name>, Built<Scope>>(
    `@clankerauth/Resource/${authentication.name}`
  );

  const layer = (options: Options) =>
    Layer.effect(service, build(authentication, declaration, options));

  const declaring: Login<Name, E | Unavailable> = authentication;

  const provider = Authentication.layer(
    declaring,
    Effect.gen(function* () {
      const { verifier, resource, protectedResource } = yield* service;
      const { host } = new URL(resource);
      const warned = yield* Ref.make(protectedResource === undefined);

      const noteHost = Effect.gen(function* () {
        if (yield* Ref.get(warned)) {
          return;
        }

        const reached = (yield* HttpServerRequest.HttpServerRequest).headers[
          "host"
        ];

        if (reached === undefined || reached === host) {
          return;
        }

        yield* Ref.set(warned, true);
        yield* Effect.logWarning(
          `The resource ${resource} publishes discovery, but a request reached it at ${reached}: an OAuth client discovering it there refuses the mismatch. Set publicUrl to the origin this listener is reached at.`
        );
      });

      return (token: Redacted.Redacted) =>
        Effect.andThen(noteHost, authenticate(verifier, token));
    }),
    {
      protectedResource: Effect.map(
        service,
        ({ protectedResource }) => protectedResource
      ),
    }
  );

  const requires = (
    scope: Scope
  ): Effect.Effect<void, Action.Forbidden, CurrentPrincipal> =>
    Effect.flatMap(CurrentPrincipal, (principal) => {
      const refusal = lacking(principal, scope);

      return refusal === undefined ? Effect.void : Effect.fail(refusal);
    });

  const admitted = (
    scope?: Scope
  ): Authentication.Protection<CurrentPrincipal, Name> =>
    scope === undefined
      ? Authentication.protect(authentication)
      : HttpRouter.middleware((route) =>
          Effect.andThen(requires(scope), route)
        ).combine(Authentication.protect(authentication));

  const local = (subject: string): Caller => ({
    subject,
    scopes: [...scopes],
    actor: { kind: "local" },
    expiresAt: undefined,
  });

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
          }))
    ),
    { authorize: Action.allowAll }
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
