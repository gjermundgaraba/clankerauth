import { Context, Effect, Layer, Redacted } from "effect";
import type { Kysely } from "kysely";
import { getCurrentAdapter } from "@better-auth/core/context";
import { betterAuth, type Auth, type BetterAuthOptions } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { apiKey } from "@better-auth/api-key";
import { jwt, type JwtOptions } from "better-auth/plugins/jwt";
import { cimd } from "@better-auth/cimd";
import {
  getOAuthProviderState,
  oauthProvider,
  type ClientMetadataResourceFetch,
} from "@better-auth/oauth-provider";
import { getMigrations } from "better-auth/db/migration";
import * as KeyList from "@gjermundgaraba/clankerauth-sdk/key-list";
import {
  administrationIdentifier,
  administrationScopes,
  MAXIMUM_PASSWORD_LENGTH,
  MINIMUM_PASSWORD_LENGTH,
} from "@clankerauth/admin-api";
import { Database, type DatabaseSchema } from "../platform/sqlite.ts";
import { CimdTransport } from "../platform/cimd-transport.ts";
import { peerHeader } from "../platform/node-http.ts";
import { resourceReference } from "../authorization/authorization.ts";
import { exactlyOneResource, protocolScopes, ResourceCatalog } from "../resources/catalog.ts";
import { signer } from "./signing.ts";
import { Settings, type IssuerSettings } from "./settings.ts";

const isString = (value: unknown): value is string => typeof value === "string";

/** Access tokens from OAuth flows and forward auth alike expire after fifteen minutes. */
export const accessTokenLifetime = 15 * 60;

type RunCallback = <A, E>(effect: Effect.Effect<A, E>) => Promise<A>;

const providerOptions = (
  settings: IssuerSettings,
  kysely: Kysely<DatabaseSchema>,
  catalog: ResourceCatalog["Service"],
  cimdTransport: ClientMetadataResourceFetch,
  runCallback: RunCallback,
  ownerExists: () => Promise<boolean>,
) => {
  // The provider and forward auth both name the OAuth issuer, which is the provider's own default.
  const jwtOptions = {
    disableSettingJwtHeader: true,
    jwt: { issuer: `${settings.baseURL}/api/auth` },
    jwks: { keyPairConfig: { alg: "EdDSA", crv: "Ed25519" } },
  } satisfies JwtOptions;

  const oauthPlugin = oauthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    scopes: [...protocolScopes],
    // The administration resource is fixed: every start re-applies its name and scopes.
    resources: [
      {
        identifier: administrationIdentifier(settings.baseURL),
        name: "clankerauth administration",
        allowedScopes: [...protocolScopes, administrationScopes.read, administrationScopes.write],
      },
    ],
    resourceSeedMode: "merge",
    rateLimit: { register: { window: 60, max: 10 } },
    postLogin: {
      page: "/consent",
      shouldRedirect: () => false,
      consentReferenceId: async ({ scopes }) => {
        const state = await getOAuthProviderState();
        const query = new URLSearchParams(state?.query);
        const identifiers = query.getAll("resource");

        if (identifiers.length !== 1 || !(await runCallback(catalog.get(identifiers[0]))))
          throw new APIError("BAD_REQUEST", {
            error: "invalid_target",
            error_description: exactlyOneResource,
          });
        const clientId = query.get("client_id");

        if (!clientId || !(await runCallback(catalog.hasAccess(clientId, identifiers[0]))))
          throw new APIError("BAD_REQUEST", {
            error: "invalid_target",
            error_description: "Client access is required",
          });
        const allowed = await runCallback(catalog.scopesFor(identifiers));

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
    // Client access is enforced by consentReferenceId above, where an automatic client
    // may ask for any resource and a managed one only for its own. The provider's check
    // would need every automatic client linked to every resource.
    enforcePerClientResources: false,
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

  const options = {
    appName: "clankerauth",
    baseURL: settings.baseURL,
    secret: Redacted.value(settings.secret),
    database: { db: kysely, type: "sqlite", transaction: true },
    trustedOrigins: [settings.baseURL],
    logger: { disabled: true },
    disabledPaths: ["/token"],
    emailAndPassword: {
      enabled: true,
      minPasswordLength: MINIMUM_PASSWORD_LENGTH,
      maxPasswordLength: MAXIMUM_PASSWORD_LENGTH,
    },
    databaseHooks: {
      user: {
        create: {
          before: async () => {
            if (await ownerExists())
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

          // Automatic clients may ask for any resource with consent, so a registration's
          // own resource list means nothing here; the provider would refuse it instead.
          delete ctx.body.resources;
        }
      }),
    },
    // The owner's session is the single sign-on session across first-party clients.
    session: { expiresIn: 60 * 60 * 24 * 30, updateAge: 60 * 60 * 24 },
    advanced: { ipAddress: { ipAddressHeaders: [peerHeader] } },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 100,
      customRules: { "/sign-in/email": { window: 60, max: 5 } },
    },
    plugins: [
      apiKey({
        defaultPrefix: KeyList.keyPrefix,
        maximumNameLength: 100,
        enableSessionForAPIKeys: false,
        keyExpiration: { defaultExpiresIn: null, minExpiresIn: 0 },
        // The plugin counts verifications through its own endpoint, which nothing calls:
        // resource servers verify keys offline, against key lists.
        rateLimit: { enabled: false },
      }),
      jwt(jwtOptions),
      signer(jwtOptions),
      oauthPlugin,
      cimd({
        fetchClientMetadataResource: cimdTransport,
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

  return { options, oauthPlugin };
};

type ProviderOptions = ReturnType<typeof providerOptions>["options"];

/** The Better Auth instance this issuer is built on. */
export type ProviderAuth = Auth<ProviderOptions>;

/** The provider's resolved context: its adapter, cookie names and secret. */
export type ProviderContext = Awaited<ProviderAuth["$context"]>;

/**
 * The authorization server: Better Auth with its plugins, migrated and initialized on the
 * issuer's database. Its scope must outlive the HTTP server's: request fibers settle
 * before the connection closes.
 */
export class Issuer extends Context.Service<
  Issuer,
  {
    readonly auth: ProviderAuth;
    readonly context: ProviderContext;
    /** Replaces the scopes the provider accepts, which are every resource's. */
    readonly publishScopes: (scopes: readonly string[]) => Effect.Effect<void>;
  }
>()("clankerauth/Issuer") {
  static readonly layer = Layer.effect(
    Issuer,
    Effect.gen(function* () {
      const settings = yield* Settings;
      const { kysely } = yield* Database;
      const catalog = yield* ResourceCatalog;
      const { fetch } = yield* CimdTransport;
      // Construction is application-scoped. Provider callbacks inherit these services,
      // never a later request's identity or scope.
      const runCallback = Effect.runPromiseWith(yield* Effect.context<never>());

      const { options, oauthPlugin } = providerOptions(
        settings,
        kysely,
        catalog,
        fetch,
        runCallback,
        // Runs inside the provider's sign-up transaction, so it must use that adapter.
        async () => {
          const adapter = await getCurrentAdapter((await auth.$context).adapter);

          return (await adapter.count({ model: "user" })) > 0;
        },
      );

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

      return {
        auth,
        context,
        publishScopes: (scopes) =>
          Effect.sync(() => {
            oauthPlugin.options.scopes = [...scopes];
          }),
      };
    }),
  );
}
