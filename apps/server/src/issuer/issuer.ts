import { apiKey } from "@better-auth/api-key";
import { cimd } from "@better-auth/cimd";
import { getCurrentAdapter } from "@better-auth/core/context";
import {
  getOAuthProviderState,
  oauthProvider,
} from "@better-auth/oauth-provider";
import type { ClientMetadataResourceFetch } from "@better-auth/oauth-provider";
import {
  administrationIdentifier,
  administrationScopes,
  MAXIMUM_PASSWORD_LENGTH,
  MINIMUM_PASSWORD_LENGTH,
} from "@gjermundgaraba/clankerauth-admin-api";
import * as KeyList from "@gjermundgaraba/clankerauth-sdk/key-list";
import { betterAuth } from "better-auth";
import type { Auth, BetterAuthOptions } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { getAdapter } from "better-auth/db/adapter";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins/jwt";
import type { JwtOptions } from "better-auth/plugins/jwt";
import { Context, Effect, Layer, Predicate, Redacted } from "effect";
import type { Kysely } from "kysely";

import { resourceReference } from "../authorization/authorization.ts";
import { CimdTransport } from "../platform/cimd-transport.ts";
import { peerHeader } from "../platform/node-http.ts";
import { Database } from "../platform/sqlite.ts";
import type { DatabaseSchema } from "../platform/sqlite.ts";
import {
  exactlyOneResource,
  protocolScopes,
  ResourceCatalog,
} from "../resources/catalog.ts";
import { SchemaRepairRequired } from "./errors.ts";
import { Settings } from "./settings.ts";
import type { IssuerSettings } from "./settings.ts";
import { signer } from "./signing.ts";

export const accessTokenLifetime = 15 * 60;

export const refreshTokenReuseSeconds = 30;

type RunCallback = <A, E>(effect: Effect.Effect<A, E>) => Promise<A>;

const providerOptions = (
  settings: IssuerSettings,
  kysely: Kysely<DatabaseSchema>,
  catalog: ResourceCatalog["Service"],
  cimdTransport: ClientMetadataResourceFetch,
  runCallback: RunCallback
) => {
  const jwtOptions = {
    disableSettingJwtHeader: true,
    jwt: { issuer: `${settings.baseURL}/api/auth` },
    jwks: { keyPairConfig: { alg: "EdDSA", crv: "Ed25519" } },
  } satisfies JwtOptions;

  const oauthPlugin = oauthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    scopes: [...protocolScopes],
    resources: [
      {
        identifier: administrationIdentifier(settings.baseURL),
        name: "clankerauth administration",
        allowedScopes: [
          ...protocolScopes,
          administrationScopes.read,
          administrationScopes.write,
        ],
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
        const [identifier] = identifiers;

        if (
          identifier === undefined ||
          identifiers.length !== 1 ||
          !(await runCallback(catalog.get(identifier)))
        ) {
          throw new APIError("BAD_REQUEST", {
            error: "invalid_target",
            error_description: exactlyOneResource,
          });
        }

        const clientId = query.get("client_id");

        if (
          clientId === null ||
          clientId === "" ||
          !(await runCallback(catalog.hasAccess(clientId, identifier)))
        ) {
          throw new APIError("BAD_REQUEST", {
            error: "invalid_target",
            error_description: "Client access is required",
          });
        }

        const allowed = await runCallback(catalog.scopesFor(identifiers));

        if (scopes.some((scope) => !allowed.includes(scope))) {
          throw new APIError("BAD_REQUEST", {
            error: "invalid_scope",
            error_description:
              "Resource scopes changed; start authorization again",
          });
        }

        return resourceReference(identifier);
      },
    },
    grantTypes: ["authorization_code", "refresh_token"],
    allowDynamicClientRegistration: true,
    allowUnauthenticatedClientRegistration: true,
    clientRegistrationRequirePKCE: true,
    // why: consentReferenceId enforces access; the provider's check would need every client linked
    enforcePerClientResources: false,
    accessTokenExpiresIn: accessTokenLifetime,
    refreshTokenExpiresIn: 60 * 60 * 24 * 30,
    refreshTokenReuseInterval: refreshTokenReuseSeconds,
    codeExpiresIn: 120,
    // why: setup creates the only account, so any authenticated user is the owner
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
            // why: runs inside the provider's sign-up transaction, so it must use that adapter
            const adapter = await getCurrentAdapter(await getAdapter(options));

            if ((await adapter.count({ model: "user" })) > 0) {
              throw new APIError("CONFLICT", {
                message: "Setup already completed",
              });
            }
          },
        },
      },
    },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        const body: unknown = ctx.body;

        // why: the provider defaults to web clients, which refuse MCP clients' loopback redirects
        if (ctx.path === "/oauth2/register" && Predicate.isObject(body)) {
          const redirects = body["redirect_uris"];

          if (
            !Predicate.isTruthy(body["application_type"]) &&
            Array.isArray(redirects) &&
            redirects.some((uri) => {
              if (!Predicate.isString(uri)) {
                return false;
              }

              try {
                return new URL(uri).protocol !== "https:";
              } catch {
                return false;
              }
            })
          ) {
            body["application_type"] = "native";
          }

          // why: consent picks the resources; the provider would refuse a registration's list
          delete body["resources"];
        }
      }),
    },
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
        // why: the plugin rate-limits its verify endpoint, which offline verification never calls
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
      // why: provider callbacks get these services, never a later request's identity or scope
      const runCallback = Effect.runPromiseWith(yield* Effect.context());

      const { options, oauthPlugin } = providerOptions(
        settings,
        kysely,
        catalog,
        fetch,
        runCallback
      );

      // why: migration and initialization cannot be cancelled, so the database must outlive them
      const initialized = yield* Effect.gen(function* () {
        const plan = yield* Effect.tryPromise(
          async () => await getMigrations(options)
        );

        if (plan.schemaProblems.length) {
          return yield* new SchemaRepairRequired({
            message: "Database schema requires manual repair",
          });
        }

        yield* Effect.tryPromise(async () => {
          await plan.runMigrations();
        });

        const auth = betterAuth(options);

        const context = yield* Effect.tryPromise(
          async () => await auth.$context
        );

        // why: the provider mints a missing signing key on first use, and two first uses mint two.
        yield* Effect.tryPromise(async () => await auth.api.getJwks());

        return { auth, context };
      }).pipe(Effect.uninterruptible, Effect.withSpan("Auth.initialize"));

      return {
        ...initialized,
        publishScopes: (scopes) =>
          Effect.sync(() => {
            oauthPlugin.options.scopes = [...scopes];
          }),
      };
    })
  );
}
