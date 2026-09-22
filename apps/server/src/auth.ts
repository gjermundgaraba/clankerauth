import { Context, Effect, Layer, Redacted, Schema, Semaphore } from "effect";
import { openDatabase, persisted } from "./database.ts";
import { getCurrentAdapter } from "@better-auth/core/context";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { apiKey } from "@better-auth/api-key";
import { jwt, type JwtOptions } from "better-auth/plugins/jwt";
import { cimd } from "@better-auth/cimd";
import { Conflict } from "@clankerauth/admin-api";
import { forwardTokens } from "./forward-auth.ts";
import { fetchClientMetadataResource } from "./cimd-transport.ts";
import { clientStore } from "./clients.ts";
import {
  getOAuthProviderState,
  oauthProvider,
  type ClientMetadataResourceFetch,
} from "@better-auth/oauth-provider";
import { provider } from "./api-errors.ts";
import { getMigrations } from "better-auth/db/migration";
import type { Settings } from "./config.ts";
import {
  mcpResource,
  mcpScope,
  protocolScopes,
  resourceReference,
  resourceStore,
} from "./resources.ts";

const isString = (value: unknown): value is string => typeof value === "string";

const decodeOwnerRow = persisted(Schema.Struct({ id: Schema.String }));

/** Access tokens from OAuth flows and forward auth alike expire after fifteen minutes. */
export const accessTokenLifetime = 15 * 60;

/** Outbound transports a test replaces; production uses the secure Node implementations. */
export interface Integrations {
  readonly cimdTransport?: ClientMetadataResourceFetch;
}

const openAuth = Effect.fn("Auth.open")(function* (settings: Settings, integrations: Integrations) {
  // The provider and forward auth both name the OAuth issuer, which is the provider's own default.
  const jwtOptions = {
    disableSettingJwtHeader: true,
    jwt: { issuer: `${settings.baseURL}/api/auth` },
    jwks: { keyPairConfig: { alg: "EdDSA", crv: "Ed25519" } },
  } satisfies JwtOptions;

  // Construction is application-scoped. Provider callbacks inherit these services,
  // never a later request's identity or scope.
  const runCallback = Effect.runPromiseWith(yield* Effect.context<never>());
  yield* Effect.try(() => mkdirSync(dirname(settings.database), { recursive: true, mode: 0o700 }));

  const database = yield* Effect.acquireRelease(
    Effect.tryPromise(() => openDatabase(settings.database)),
    (open) => Effect.promise(() => open.close()),
  );

  const { sql } = database;
  const clients = clientStore(database.kysely);

  // Setup creates the only account, so the owner is whichever user exists.
  const owner = Effect.fn("Auth.owner")(function* () {
    const rows = yield* sql`SELECT id FROM user LIMIT 1`;

    if (!rows.length) return undefined;

    return (yield* decodeOwnerRow(rows[0])).id;
  });

  const oauthPlugin = oauthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    scopes: [...protocolScopes],
    // The provider seeds this once and never reverts the owner's later name edits.
    resources: [
      {
        identifier: mcpResource(settings.baseURL),
        name: "Clanker Auth administration",
        allowedScopes: [...protocolScopes, mcpScope],
      },
    ],
    rateLimit: { register: { window: 60, max: 10 } },
    postLogin: {
      page: "/consent",
      shouldRedirect: () => false,
      consentReferenceId: async ({ scopes }) => {
        const state = await getOAuthProviderState();
        const query = new URLSearchParams(state?.query);
        const identifiers = query.getAll("resource");

        if (identifiers.length !== 1 || !(await runCallback(resources.get(identifiers[0]))))
          throw new APIError("BAD_REQUEST", {
            error: "invalid_target",
            error_description: "Choose exactly one Resource",
          });
        const clientId = query.get("client_id");

        if (!clientId || !(await runCallback(resources.hasAccess(clientId, identifiers[0]))))
          throw new APIError("BAD_REQUEST", {
            error: "invalid_target",
            error_description: "Client access is required",
          });
        const allowed = await runCallback(resources.scopesFor(identifiers));

        if (scopes.some((scope) => !allowed.includes(scope)))
          throw new APIError("BAD_REQUEST", {
            error: "invalid_scope",
            error_description: "Resource scopes changed; start authorization again",
          });

        return resourceReference(identifiers[0]);
      },
    },
    grantTypes: ["authorization_code", "refresh_token"],
    allowDynamicClientRegistration: true,
    allowUnauthenticatedClientRegistration: true,
    clientRegistrationRequirePKCE: true,
    clientRegistrationDefaultResources: Array<string>(),
    enforcePerClientResources: true,
    accessTokenExpiresIn: accessTokenLifetime,
    refreshTokenExpiresIn: 60 * 60 * 24 * 30,
    // A retried refresh inside the window replays the same replacement instead of revoking the family.
    refreshTokenReuseInterval: 30,
    codeExpiresIn: 120,
    // Setup creates the only account; any authenticated user is the owner.
    clientPrivileges: async ({ user, action }) =>
      !!user && action !== "configure-client-credentials-scopes",
    resourcePrivileges: async ({ user }) => !!user,
  });

  const resources = yield* resourceStore(
    sql,
    () => auth,
    (scopes, identifiers) => {
      oauthPlugin.options.scopes = scopes;
      oauthPlugin.options.clientRegistrationDefaultResources = identifiers;
    },
    mcpResource(settings.baseURL),
  );

  const options = {
    appName: "Clanker Auth",
    baseURL: settings.baseURL,
    secret: Redacted.value(settings.secret),
    database: { db: database.kysely, type: "sqlite", transaction: true },
    trustedOrigins: [settings.baseURL],
    logger: { disabled: true },
    disabledPaths: ["/token"],
    emailAndPassword: { enabled: true, minPasswordLength: 8, maxPasswordLength: 128 },
    databaseHooks: {
      user: {
        create: {
          // Runs inside the provider's sign-up transaction, so it must use that adapter.
          before: async () => {
            const adapter = await getCurrentAdapter((await auth.$context).adapter);

            if (await adapter.count({ model: "user" }))
              throw new APIError("CONFLICT", { message: "Setup already completed" });
          },
        },
      },
    },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        // The provider registers web clients by default, which forbids loopback callbacks.
        // MCP clients commonly omit application_type while using loopback redirects.
        if (ctx.path === "/oauth2/register") {
          const redirects = ctx.body.redirect_uris;

          if (
            !ctx.body.application_type &&
            Array.isArray(redirects) &&
            redirects.some((uri) => {
              if (!isString(uri)) return false;

              try {
                return new URL(uri).protocol !== "https:";
              } catch {
                return false;
              }
            })
          )
            ctx.body.application_type = "native";
        }
      }),
    },
    // The owner's session is the single sign-on session across first-party clients.
    session: { expiresIn: 60 * 60 * 24 * 30, updateAge: 60 * 60 * 24 },
    advanced: { ipAddress: { ipAddressHeaders: ["x-clankerauth-peer"] } },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 100,
      customRules: { "/sign-in/email": { window: 60, max: 5 } },
    },
    plugins: [
      apiKey({
        defaultPrefix: "ca_",
        maximumNameLength: 100,
        enableSessionForAPIKeys: false,
        keyExpiration: { defaultExpiresIn: null, minExpiresIn: 0 },
        rateLimit: { enabled: true, timeWindow: 60_000, maxRequests: 1000 },
      }),
      jwt(jwtOptions),
      forwardTokens(jwtOptions, accessTokenLifetime),
      oauthPlugin,
      cimd({
        fetchClientMetadataResource: (input, init) =>
          (integrations.cimdTransport ?? fetchClientMetadataResource)(input, init),
        metadataProfile: "mcp-2026-07-28",
        metadataRevalidationInterval: 300,
        maxCacheEntries: 1000,
        metadataFetchPolicy: {
          maximumConcurrentFetches: 8,
          maximumConcurrentFetchesPerOrigin: 2,
          maximumFetchesPerMinute: 60,
          maximumFetchesPerOriginPerMinute: 15,
        },
      }),
    ],
  } satisfies BetterAuthOptions;

  // Migrations and provider initialization cannot be cancelled; they settle here so the
  // layer never hands out a service whose database finalizer could outrun them. The
  // provider is constructed after migrating, since its initialization reads the schema.
  const { auth, context } = yield* Effect.fn("Auth.initialize")(function* () {
    const plan = yield* Effect.tryPromise(() => getMigrations(options));

    if (plan.schemaProblems.length)
      return yield* Effect.fail(new Error("Database schema requires manual repair"));
    yield* Effect.tryPromise(() => plan.runMigrations());
    const auth = betterAuth(options);
    // Provider initialization seeds the administration resource; publish the catalog after it.
    const context = yield* Effect.tryPromise(() => auth.$context);

    return { auth, context };
  }, Effect.uninterruptible)();

  yield* resources.synchronize();

  return {
    auth,
    /** The provider's resolved context: its adapter, cookie names and secret. */
    context,
    sql,
    database: database.kysely,
    owner,
    settings,
    resources,
    clients,
    setup: yield* Semaphore.make(1),
  };
});

/**
 * The issuer: one SQLite connection and the Better Auth instance that owns it. Its scope
 * must outlive the HTTP server's: request fibers settle before the connection closes.
 */
export class Auth extends Context.Service<Auth, Effect.Success<ReturnType<typeof openAuth>>>()(
  "ClankerAuth/Auth",
) {
  /** Opens the database, runs the provider's migrations, and closes both with the scope. */
  static readonly layer = (settings: Settings, integrations: Integrations = {}) =>
    Layer.effect(Auth, openAuth(settings, integrations));
}

/**
 * First-run setup is the only sign-up: the provider route is not mounted, and the
 * user-creation hook refuses a second account. Setup requests are serialized so a
 * concurrent one sees the created owner and gets a conflict. The provider signs
 * the owner in; the returned cookies belong on the response.
 */
export const createOwner = Effect.fn("Auth.createOwner")(
  function* (service: Auth["Service"], input: { email: string; password: string }) {
    if (yield* service.owner())
      return yield* Effect.fail(new Conflict({ error: "Setup already completed" }));

    const { headers } = yield* provider(() =>
      service.auth.api.signUpEmail({
        body: { name: "Owner", email: input.email.trim(), password: input.password },
        returnHeaders: true,
      }),
    );

    return headers.getSetCookie();
  },
  (effect, service) => service.setup.withPermit(effect),
);
