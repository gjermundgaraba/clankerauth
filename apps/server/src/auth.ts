import { Clock, Effect, Option, Redacted, Schema } from "effect";
import { getCurrentAuthEndpointContext } from "@better-auth/core/context";
import { transaction, openDatabase } from "./database.ts";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { apiKey } from "@better-auth/api-key";
import { jwt } from "better-auth/plugins";
import { cimd } from "@better-auth/cimd";
import { fetchClientMetadataResource } from "./cimd-transport.ts";
import { onboardingStore } from "./onboarding.ts";
import {
  getOAuthProviderState,
  oauthProvider,
  type ClientMetadataResourceFetch,
} from "@better-auth/oauth-provider";
import { provider } from "./api-errors.ts";
import { getMigrations } from "better-auth/db/migration";
import type { Settings } from "./config.ts";
import { mcpResource, protocolScopes, resourceReference, resourceStore } from "./resources.ts";

const ClientIdCarrier = Schema.Struct({ client_id: Schema.String });

const OAuthQueryCarrier = Schema.Struct({ oauth_query: Schema.String });

const isString = (value: unknown): value is string => typeof value === "string";

export const openAuth = Effect.fn("Auth.open")(function* (
  settings: Settings,
  integrations: { cimdTransport?: ClientMetadataResourceFetch } = {},
) {
  // Construction is application-scoped. Provider callbacks inherit these services,
  // never a later request's identity or scope.
  const runCallback = Effect.runPromiseWith(yield* Effect.context<never>());
  yield* Effect.try(() => mkdirSync(dirname(settings.database), { recursive: true, mode: 0o700 }));
  const database = yield* Effect.tryPromise(() => openDatabase(settings.database));
  const { sql } = database;
  const onboarding = onboardingStore(database.kysely);

  const owner = Effect.fn("Auth.owner")(function* () {
    const rows = yield* sql`SELECT userId FROM serviceOwner WHERE id = 1`;

    if (!rows.length) return undefined;

    return (yield* Schema.decodeUnknownEffect(Schema.Struct({ userId: Schema.String }))(rows[0]))
      .userId;
  });

  const oauthPlugin = oauthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    scopes: [...protocolScopes],
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
    accessTokenExpiresIn: 300,
    refreshTokenExpiresIn: 60 * 60 * 24 * 30,
    codeExpiresIn: 120,
    refreshTokenReuseInterval: 0,
    // Session-backed DCR needs a source marker distinct from owner-managed clients.
    // Anonymous DCR is already unowned; both are tracked by the creation trigger.
    clientReference: () =>
      getCurrentAuthEndpointContext().path === "/oauth2/register" ? "clankerauth:dcr" : undefined,
    // Setup creates the only account; any authenticated user is the owner.
    clientPrivileges: async ({ user, action }) =>
      !!user && action !== "configure-client-credentials-scopes",
    resourcePrivileges: async ({ user }) => !!user,
  });

  const resources = resourceStore(
    sql,
    () => serviceAuth(),
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
    emailAndPassword: {
      enabled: true,
      disableSignUp: true,
      minPasswordLength: 8,
      maxPasswordLength: 128,
    },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        const clientId = Option.getOrElse(
          Option.map(
            Schema.decodeUnknownOption(ClientIdCarrier)(ctx.body),
            (value) => value.client_id,
          ),
          () =>
            Option.getOrElse(
              Option.map(
                Schema.decodeUnknownOption(ClientIdCarrier)(ctx.query),
                (value) => value.client_id,
              ),
              () =>
                Option.match(Schema.decodeUnknownOption(OAuthQueryCarrier)(ctx.body), {
                  onNone: () => undefined,
                  onSome: ({ oauth_query }) =>
                    new URLSearchParams(oauth_query).get("client_id") ?? undefined,
                }),
            ),
        );

        if (
          clientId &&
          ["/oauth2/authorize", "/oauth2/consent", "/oauth2/continue"].includes(ctx.path) &&
          (await runCallback(onboarding.isBlocked(clientId)))
        )
          throw new APIError("BAD_REQUEST", {
            error: "invalid_client",
            error_description: "Client is blocked",
          });

        if (ctx.path === "/oauth2/register") {
          if (!(await runCallback(onboarding.admit())))
            throw new APIError("TOO_MANY_REQUESTS", {
              error: "temporarily_unavailable",
              error_description: "Client registration capacity reached",
            });
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
    session: { expiresIn: 60 * 60 * 24 * 30, updateAge: 60 * 60 * 24, freshAge: 0 },
    advanced: { ipAddress: { ipAddressHeaders: ["x-clankerauth-peer"] } },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 100,
      customRules: {
        "/sign-in/email": { window: 60, max: 5 },
        "/oauth2/register": { window: 60, max: 10 },
      },
    },
    plugins: [
      apiKey({
        defaultPrefix: "ca_",
        maximumNameLength: 100,
        enableSessionForAPIKeys: false,
        keyExpiration: { defaultExpiresIn: null, minExpiresIn: 0 },
        rateLimit: { enabled: true, timeWindow: 60_000, maxRequests: 1000 },
      }),
      jwt({
        disableSettingJwtHeader: true,
        jwks: { keyPairConfig: { alg: "EdDSA", crv: "Ed25519" } },
      }),
      oauthPlugin,
      cimd({
        fetchClientMetadataResource: async (input, init) => {
          // Reclaim abandoned registrations during discovery without an admission gate.
          await runCallback(onboarding.cleanup());

          return (integrations.cimdTransport ?? fetchClientMetadataResource)(input, init);
        },
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

  // Defer provider initialization until migrations finish.
  const makeAuth = () => betterAuth(options);
  let auth: ReturnType<typeof makeAuth> | undefined;
  const serviceAuth = () => (auth ??= makeAuth());
  // Track work for shutdown without serializing independent requests.
  const active = new Set<Promise<unknown>>();
  let closing = false;

  const run = <T>(operation: () => Promise<T>) => {
    if (closing)
      return Promise.reject(new APIError("SERVICE_UNAVAILABLE", { message: "Service stopping" }));
    const result = Promise.resolve().then(operation);
    active.add(result);
    void result.then(
      () => active.delete(result),
      () => active.delete(result),
    );

    return result;
  };

  // Request scopes may finish asynchronous finalizers after their HTTP response.
  // Keep those lifetimes admitted until all provider cleanup has completed.
  const retain = () => {
    if (closing) throw new APIError("SERVICE_UNAVAILABLE", { message: "Service stopping" });
    const lifetime = Promise.withResolvers<void>();
    active.add(lifetime.promise);

    return () => {
      active.delete(lifetime.promise);
      lifetime.resolve();
    };
  };

  const close = async () => {
    closing = true;
    await Promise.allSettled(active);
    await database.close();
  };

  return {
    get auth() {
      return serviceAuth();
    },
    options,
    sql,
    database: database.kysely,
    owner,
    settings,
    resources,
    onboarding,
    run,
    retain,
    close,
  };
});

export type Service = Effect.Success<ReturnType<typeof openAuth>>;

export const initialize = Effect.fn("Auth.initialize")(function* (service: Service) {
  const plan = yield* Effect.tryPromise(() => getMigrations(service.options));

  if (plan.schemaProblems.length)
    return yield* Effect.fail(new Error("Database schema requires manual repair"));
  yield* Effect.tryPromise(() => plan.runMigrations());
  yield* sqlInitialize(service);
  yield* Effect.tryPromise(() => service.auth.$context);
}, Effect.uninterruptible);

const sqlInitialize = (service: Service) =>
  Effect.gen(function* () {
    yield* service.sql`CREATE TABLE IF NOT EXISTS serviceOwner (id INTEGER PRIMARY KEY CHECK(id = 1), userId TEXT NOT NULL UNIQUE REFERENCES user(id))`;

    if (!(yield* service.owner()) && (yield* service.sql`SELECT id FROM user LIMIT 1`).length)
      return yield* Effect.fail(new Error("Database contains accounts without an owner marker"));
    yield* service.sql`CREATE TABLE IF NOT EXISTS clientOnboarding (clientId TEXT PRIMARY KEY, source TEXT NOT NULL CHECK(source IN ('dcr', 'cimd')), blocked INTEGER NOT NULL DEFAULT 0 CHECK(blocked IN (0, 1)))`;
    // Enforce the bound inside canonical persistence, including cached CIMD recreation.
    yield* service.sql`CREATE TRIGGER IF NOT EXISTS automaticClientCapacity BEFORE INSERT ON clientOnboarding
      WHEN NOT EXISTS (SELECT 1 FROM clientOnboarding WHERE clientId = NEW.clientId)
        AND (SELECT count(*) FROM clientOnboarding) >= 1000
      BEGIN SELECT RAISE(ABORT, 'Automatic client capacity reached'); END`;
    // Managed creation always has an owner. DCR is anonymous or carries the
    // server-owned reference above; CIMD supplies its discovery provenance.
    // This runs in the provider's transaction, so tracking failure rolls back registration.
    yield* service.sql`CREATE TRIGGER IF NOT EXISTS automaticClientProvenance AFTER INSERT ON oauthClient
      WHEN NEW.clientDiscoveryId IS NOT NULL OR NEW.userId IS NULL OR NEW.referenceId = 'clankerauth:dcr'
      BEGIN
        INSERT OR IGNORE INTO clientOnboarding (clientId, source, blocked)
          VALUES (NEW.clientId, CASE WHEN NEW.clientDiscoveryId IS NOT NULL THEN 'cimd' ELSE 'dcr' END, 0);
        UPDATE oauthClient SET disabled = 1 WHERE clientId = NEW.clientId
          AND EXISTS (SELECT 1 FROM clientOnboarding WHERE clientId = NEW.clientId AND blocked = 1);
      END`;
    // Every insertion, including deterministic CIMD recreation, gets a fresh identity.
    // Keeping the generation on the live row bounds its lifetime to the client.
    yield* service.sql`CREATE TRIGGER IF NOT EXISTS clientGrantGeneration AFTER INSERT ON oauthClient
      BEGIN
        UPDATE oauthClient SET grantGeneration = lower(hex(randomblob(16))) WHERE clientId = NEW.clientId;
      END`;
    // Security-relevant document changes revoke grants in the same transaction
    // as metadata reconciliation; plugin notifications are only best effort.
    yield* service.sql`CREATE TRIGGER IF NOT EXISTS cimdMetadataRevocation AFTER UPDATE OF redirectUris, tokenEndpointAuthMethod, jwks, jwksUri, name, uri ON oauthClient
      WHEN NEW.clientDiscoveryId IS NOT NULL AND (OLD.redirectUris IS NOT NEW.redirectUris OR OLD.tokenEndpointAuthMethod IS NOT NEW.tokenEndpointAuthMethod OR OLD.jwks IS NOT NEW.jwks OR OLD.jwksUri IS NOT NEW.jwksUri OR OLD.name IS NOT NEW.name OR OLD.uri IS NOT NEW.uri)
      BEGIN
        UPDATE oauthClient SET grantGeneration = lower(hex(randomblob(16))) WHERE clientId = NEW.clientId;
        DELETE FROM oauthConsent WHERE clientId = NEW.clientId;
        DELETE FROM verification WHERE json_valid(value) AND json_extract(value, '$.type') = 'authorization_code' AND json_extract(value, '$.query.client_id') = NEW.clientId;
        DELETE FROM oauthAccessToken WHERE clientId = NEW.clientId;
        DELETE FROM oauthRefreshToken WHERE clientId = NEW.clientId;
      END`;
    yield* service.resources.initialize();
  });

export const createOwner = Effect.fn("Auth.createOwner")(function* (
  service: Service,
  input: { email: string; password: string },
) {
  if (yield* service.owner())
    return yield* Effect.fail(new APIError("CONFLICT", { message: "Setup already completed" }));
  const email = input.email.trim().toLowerCase();
  const context = yield* provider(() => service.auth.$context);

  // Match the pinned provider's email validator: setup must produce a usable login.
  if (
    email.length > 254 ||
    !/^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+.-]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,}$/.test(
      email,
    ) ||
    input.password.length < context.password.config.minPasswordLength ||
    input.password.length > context.password.config.maxPasswordLength
  )
    return yield* Effect.fail(
      new APIError("BAD_REQUEST", { message: "Invalid email or password" }),
    );
  const hash = yield* provider(() => context.password.hash(input.password));
  // Hash outside the transaction; account creation and ownership commit together.
  yield* transaction(service.database, (sql) =>
    Effect.gen(function* () {
      if ((yield* sql`SELECT 1 FROM serviceOwner WHERE id = 1`).length)
        return yield* Effect.fail(new APIError("CONFLICT", { message: "Setup already completed" }));
      const id = randomUUID();
      const now = yield* Clock.currentTimeMillis;
      yield* sql`INSERT INTO user (id, name, email, emailVerified, createdAt, updatedAt)
      VALUES (${id}, 'Owner', ${email}, 0, ${now}, ${now})`;
      yield* sql`INSERT INTO account (id, accountId, providerId, userId, password, createdAt, updatedAt)
      VALUES (${randomUUID()}, ${id}, 'credential', ${id}, ${hash}, ${now}, ${now})`;
      yield* sql`INSERT INTO serviceOwner (id, userId) VALUES (1, ${id})`;
    }),
  );
});
