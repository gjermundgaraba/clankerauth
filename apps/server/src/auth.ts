import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError, createAuthMiddleware, getAuthoritativeSessionFromCtx } from "better-auth/api";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { getMigrations } from "better-auth/db/migration";
import type { Settings } from "./config.ts";

export function openAuth(settings: Settings) {
  mkdirSync(dirname(settings.database), { recursive: true, mode: 0o700 });
  const db = new Database(settings.database);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("busy_timeout = 5000");
  const owner = () =>
    db.prepare<[], { userId: string }>("SELECT userId FROM serviceOwner WHERE id = 1").get()
      ?.userId;
  const scopes = [
    ...new Set([
      "openid",
      "profile",
      "email",
      "offline_access",
      ...settings.resources.flatMap((r) => r.scopes),
    ]),
  ];
  const options = {
    appName: "Clanker Auth",
    baseURL: settings.baseURL,
    secret: settings.secret,
    database: db,
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
            if (session.userId !== owner())
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
        if (session && session.user.id !== owner())
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
          (!("sub" in result) || result.sub !== owner())
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
      oauthProvider({
        loginPage: "/login",
        consentPage: "/consent",
        scopes,
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
        customTokenResponseFields: ({ user }) => {
          if (!user || user.id !== owner())
            throw new APIError("BAD_REQUEST", {
              error: "invalid_grant",
              error_description: "Owner grant required",
            });
          return {};
        },
        customUserInfoClaims: ({ user }) => {
          if (user.id !== owner()) throw new APIError("UNAUTHORIZED", { error: "invalid_token" });
          return {};
        },
        resources: settings.resources.map((r) => ({
          identifier: r.identifier,
          name: r.name,
          allowedScopes: ["openid", "profile", "email", "offline_access", ...r.scopes],
          accessTokenTtl: 300,
        })),
        resourceSeedMode: "overwrite",
        clientPrivileges: ({ user, action }) =>
          !!user && user.id === owner() && action !== "configure-client-credentials-scopes",
        resourcePrivileges: ({ user }) => !!user && user.id === owner(),
      }),
    ],
  } satisfies BetterAuthOptions;
  // Provider initialization seeds resources, so defer it until migrations finish.
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
    if (db.open) db.close();
  };
  return {
    get auth() {
      return (auth ??= makeAuth());
    },
    options,
    db,
    owner,
    settings,
    exclusive,
    close,
  };
}
export type Service = ReturnType<typeof openAuth>;

export async function initialize(service: Service) {
  const plan = await getMigrations(service.options);
  if (plan.schemaProblems.length) throw new Error("Database schema requires manual repair");
  await plan.runMigrations();
  service.db.exec(
    "CREATE TABLE IF NOT EXISTS serviceOwner (id INTEGER PRIMARY KEY CHECK(id = 1), userId TEXT NOT NULL UNIQUE REFERENCES user(id))",
  );
  if (!service.owner() && service.db.prepare("SELECT id FROM user LIMIT 1").get())
    throw new Error("Database contains accounts without an owner marker");
  await service.auth.$context;
}

export async function createOwner(service: Service, input: { email: string; password: string }) {
  if (service.owner()) throw new APIError("CONFLICT", { message: "Setup already completed" });
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
  // Keep provider hashing outside the synchronous transaction. These writes target
  // the pinned Better Auth schema so account creation and ownership commit together.
  service.db
    .transaction(() => {
      const id = randomUUID();
      const now = Date.now();
      service.db
        .prepare(
          "INSERT INTO user (id, name, email, emailVerified, createdAt, updatedAt) VALUES (?, 'Owner', ?, 0, ?, ?)",
        )
        .run(id, email, now, now);
      service.db
        .prepare(
          "INSERT INTO account (id, accountId, providerId, userId, password, createdAt, updatedAt) VALUES (?, ?, 'credential', ?, ?, ?, ?)",
        )
        .run(randomUUID(), id, id, hash, now, now);
      service.db.prepare("INSERT INTO serviceOwner (id, userId) VALUES (1, ?)").run(id);
    })
    .immediate();
}
