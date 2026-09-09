import { Effect, Schema } from "effect";
import { openDatabase } from "./database.ts";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError, createAuthMiddleware, getAuthoritativeSessionFromCtx } from "better-auth/api";
import { jwt } from "better-auth/plugins";
import { getOAuthProviderState, oauthProvider } from "@better-auth/oauth-provider";
import { getMigrations } from "better-auth/db/migration";
import type { Settings } from "./config.ts";
import { protocolScopes, resourceReference, resourceStore } from "./resources.ts";

export async function openAuth(settings: Settings) {
  mkdirSync(dirname(settings.database), { recursive: true, mode: 0o700 });
  const database = await openDatabase(settings.database);
  const { sql } = database;
  const owner = Effect.fn("Auth.owner")(function* () {
    const rows = yield* sql`SELECT userId FROM serviceOwner WHERE id = 1`;
    if (!rows.length) return undefined;
    return (yield* Schema.decodeUnknownEffect(Schema.Struct({ userId: Schema.String }))(rows[0]))
      .userId;
  });
  const provider = oauthProvider({
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
        if (identifiers.length !== 1 || !(await Effect.runPromise(resources.get(identifiers[0]))))
          throw new APIError("BAD_REQUEST", {
            error: "invalid_target",
            error_description: "Choose exactly one Resource",
          });
        const clientId = query.get("client_id");
        if (!clientId || !(await Effect.runPromise(resources.hasAccess(clientId, identifiers[0]))))
          throw new APIError("BAD_REQUEST", {
            error: "invalid_target",
            error_description: "Client access is required",
          });
        const allowed = await Effect.runPromise(resources.scopesFor(identifiers));
        if (scopes.some((scope) => !allowed.includes(scope)))
          throw new APIError("BAD_REQUEST", {
            error: "invalid_scope",
            error_description: "Resource scopes changed; start authorization again",
          });
        return resourceReference(identifiers[0]);
      },
    },
    grantTypes: ["authorization_code", "refresh_token"],
    allowDynamicClientRegistration: false,
    allowUnauthenticatedClientRegistration: false,
    enforcePerClientResources: true,
    accessTokenExpiresIn: 300,
    refreshTokenExpiresIn: 60 * 60 * 24 * 30,
    codeExpiresIn: 120,
    refreshTokenReuseInterval: 0,
    // Supported callback runs before token writes/signing for both code
    // exchange and refresh, including legacy grants without a live session.
    customTokenResponseFields: async ({ user }) => {
      if (!user || user.id !== (await Effect.runPromise(owner())))
        throw new APIError("BAD_REQUEST", {
          error: "invalid_grant",
          error_description: "Owner grant required",
        });
      return {};
    },
    customUserInfoClaims: async ({ user }) => {
      if (user.id !== (await Effect.runPromise(owner())))
        throw new APIError("UNAUTHORIZED", { error: "invalid_token" });
      return {};
    },
    clientPrivileges: async ({ user, action }) =>
      !!user &&
      user.id === (await Effect.runPromise(owner())) &&
      action !== "configure-client-credentials-scopes",
    resourcePrivileges: async ({ user }) =>
      !!user && user.id === (await Effect.runPromise(owner())),
  });
  const synchronizeScopes = () =>
    resources.supportedScopes().pipe(
      Effect.tap((scopes) =>
        Effect.sync(() => {
          provider.options.scopes = scopes;
        }),
      ),
      Effect.asVoid,
    );
  const resources = resourceStore(sql, (scopes) => {
    provider.options.scopes = scopes;
  });
  const options = {
    appName: "Clanker Auth",
    baseURL: settings.baseURL,
    secret: settings.secret,
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
    databaseHooks: {
      session: {
        create: {
          before: async (session) => {
            if (session.userId !== (await Effect.runPromise(owner())))
              throw new APIError("UNAUTHORIZED", { message: "Owner login required" });
          },
        },
      },
    },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        // A legacy cookie may be discarded or replaced, but may not authorize work.
        if (ctx.path === "/sign-out" || ctx.path === "/sign-in/email") return;
        // Login continuation carries a newly created session before the browser
        // has received its cookie. It already passed the session-creation gate.
        const session = ctx.context.newSession ?? (await getAuthoritativeSessionFromCtx(ctx));
        if (session && session.user.id !== (await Effect.runPromise(owner())))
          throw new APIError("UNAUTHORIZED", { message: "Owner session required" });
      }),
      after: createAuthMiddleware(async (ctx) => {
        // JWT and refresh introspection bypass issuance callbacks. This service
        // uses public subjects only (no pairwiseSecret or machine grants).
        if (ctx.path !== "/oauth2/introspect") return;
        const result = ctx.context.returned;
        if (
          result &&
          typeof result === "object" &&
          "active" in result &&
          result.active === true &&
          (!("sub" in result) || result.sub !== (await Effect.runPromise(owner())))
        )
          return ctx.json({ active: false });
      }),
    },
    session: { expiresIn: 60 * 60 * 12, freshAge: 60 * 15 },
    advanced: { ipAddress: { ipAddressHeaders: ["x-clankerauth-peer"] } },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 100,
      customRules: { "/sign-in/email": { window: 60, max: 5 } },
    },
    plugins: [
      jwt({
        disableSettingJwtHeader: true,
        jwks: { keyPairConfig: { alg: "EdDSA", crv: "Ed25519" } },
      }),
      provider,
    ],
  } satisfies BetterAuthOptions;
  // Defer provider initialization until migrations finish.
  const makeAuth = () => betterAuth(options);
  let auth: ReturnType<typeof makeAuth> | undefined;
  // All online operations enter here, including admin operations that call auth.api.
  // Kept on the service so multiple HTTP application wrappers share admission.
  let tail = Promise.resolve();
  let closing = false;
  const exclusive = <T>(operation: () => Promise<T>) => {
    if (closing)
      return Promise.reject(new APIError("SERVICE_UNAVAILABLE", { message: "Service stopping" }));
    const result = tail.then(operation);
    tail = result.then(
      () => {},
      () => {},
    );
    return result;
  };
  const close = async () => {
    closing = true;
    await tail;
    await database.close();
  };
  return {
    get auth() {
      return (auth ??= makeAuth());
    },
    options,
    sql,
    owner,
    settings,
    resources,
    synchronizeScopes,
    exclusive,
    close,
  };
}
export type Service = Awaited<ReturnType<typeof openAuth>>;

export async function initialize(service: Service) {
  const plan = await getMigrations(service.options);
  if (plan.schemaProblems.length) throw new Error("Database schema requires manual repair");
  await plan.runMigrations();
  await Effect.runPromise(sqlInitialize(service));
  await service.auth.$context;
}

const sqlInitialize = (service: Service) =>
  Effect.gen(function* () {
    yield* service.sql`CREATE TABLE IF NOT EXISTS serviceOwner (id INTEGER PRIMARY KEY CHECK(id = 1), userId TEXT NOT NULL UNIQUE REFERENCES user(id))`;
    if (!(yield* service.owner()) && (yield* service.sql`SELECT id FROM user LIMIT 1`).length)
      return yield* Effect.fail(new Error("Database contains accounts without an owner marker"));
    yield* service.synchronizeScopes();
  });

export async function createOwner(service: Service, input: { email: string; password: string }) {
  if (await Effect.runPromise(service.owner()))
    throw new APIError("CONFLICT", { message: "Setup already completed" });
  const email = input.email.trim().toLowerCase();
  const context = await service.auth.$context;
  // Match the pinned provider's email validator: setup must produce a usable login.
  if (
    email.length > 254 ||
    !/^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+.-]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,}$/.test(
      email,
    ) ||
    input.password.length < context.password.config.minPasswordLength ||
    input.password.length > context.password.config.maxPasswordLength
  )
    throw new APIError("BAD_REQUEST", { message: "Invalid email or password" });
  const hash = await context.password.hash(input.password);
  // Hash outside the transaction; account creation and ownership commit together.
  await Effect.runPromise(
    service.sql.withTransaction(
      Effect.gen(function* () {
        const id = randomUUID();
        const now = Date.now();
        yield* service.sql`INSERT INTO user (id, name, email, emailVerified, createdAt, updatedAt)
      VALUES (${id}, 'Owner', ${email}, 0, ${now}, ${now})`;
        yield* service.sql`INSERT INTO account (id, accountId, providerId, userId, password, createdAt, updatedAt)
      VALUES (${randomUUID()}, ${id}, 'credential', ${id}, ${hash}, ${now}, ${now})`;
        yield* service.sql`INSERT INTO serviceOwner (id, userId) VALUES (1, ${id})`;
      }),
    ),
  );
}
