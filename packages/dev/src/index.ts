import { randomBytes } from "node:crypto";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Context, Effect, Exit, Fiber, FileSystem, Layer, Redacted, Schema, Scope } from "effect";
import { NodeFileSystem } from "@effect/platform-node";
import { Cookies, FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";
import {
  ApiKeys,
  CimdTransport,
  Clients,
  issuerServices,
  listen,
  nodeHandler,
  OwnerAccount,
  ResourceCatalog,
  Resources,
  Settings,
  validateSettings,
} from "@clankerauth/server/embed";
import { CurrentOwner } from "@clankerauth/admin-api";
import type { DisposableIssuer, DisposableIssuerOptions, Identity } from "./types.d.ts";

const credentialsFile = "credentials.json";

/** The credentials file is written by this package only, so its shape is a schema. */
const IdentityFile = Schema.Struct({
  email: Schema.String,
  password: Schema.String,
  secret: Schema.String,
  clientId: Schema.optional(Schema.String),
  clientSecret: Schema.optional(Schema.String),
});

const decodeIdentity = Schema.decodeUnknownEffect(Schema.fromJsonString(IdentityFile));

const encodeIdentity = Schema.encodeSync(IdentityFile);

const saveIdentity = (directory: string, identity: Identity) =>
  Effect.flatMap(FileSystem.FileSystem, (fs) =>
    fs.writeFileString(
      join(directory, credentialsFile),
      `${JSON.stringify(encodeIdentity(identity), null, 2)}\n`,
      { mode: 0o600 },
    ),
  );

/**
 * A run's identity. A disposable issuer invents one; a persistent workspace keeps it
 * in its data directory, so the owner account, the signing secret and the registered
 * client survive a restart. The file is the whole secret: it is the workspace.
 */
const loadIdentity = Effect.fn("Dev.identity")(function* (directory: string, persistent: boolean) {
  const fresh: Identity = {
    email: "owner@example.internal",
    password: randomBytes(24).toString("base64url"),
    secret: randomBytes(32).toString("hex"),
  };

  if (!persistent) return fresh;
  const fs = yield* FileSystem.FileSystem;
  const path = join(directory, credentialsFile);

  if (yield* fs.exists(path)) return yield* decodeIdentity(yield* fs.readFileString(path));
  yield* saveIdentity(directory, fresh);

  return fresh;
});

const provisioningFailed = (cause: unknown) =>
  new Error("Disposable issuer provisioning failed", { cause });

/** Sign the owner in and seal the forward cookie, the way a browser does. */
const ownerSession = Effect.fn("Dev.ownerSession")(function* (
  issuerUrl: string,
  forwardOrigin: string | undefined,
  owner: { readonly email: string; readonly password: string },
  appOrigin: string,
) {
  if (forwardOrigin === undefined)
    return yield* Effect.fail(
      new Error("A forward-auth session needs a cookieDomain; the issuer serves none"),
    );
  const client = yield* HttpClient.HttpClient;

  const signIn = yield* client.execute(
    HttpClientRequest.post(`${issuerUrl}/api/auth/sign-in/email`, {
      headers: { origin: issuerUrl },
    }).pipe(HttpClientRequest.bodyJsonUnsafe(owner)),
  );

  // why: every response body is read to completion, so no connection is left half-consumed.
  yield* signIn.text;

  if (signIn.status !== 200)
    return yield* Effect.fail(new Error(`Owner sign-in failed with HTTP ${signIn.status}`));
  const destination = new URL("/", appOrigin).href;

  const sealed = yield* client.get(
    `${issuerUrl}/forward-auth/continue?rd=${encodeURIComponent(destination)}`,
    { headers: { cookie: Cookies.toCookieHeader(signIn.cookies) } },
  );

  yield* sealed.text;
  const jar = Cookies.merge(signIn.cookies, sealed.cookies);

  return {
    cookie: Cookies.toCookieHeader(jar),
    cookies: Object.entries(Cookies.toRecord(jar)).map(([name, value]) => ({ name, value })),
  };
});

/** The platform this package runs on. A forward-auth answer is read, never followed. */
const platform = Layer.mergeAll(
  NodeFileSystem.layer,
  FetchHttpClient.layer,
  Layer.succeed(FetchHttpClient.RequestInit, { redirect: "manual" }),
);

/**
 * One running issuer, built into the caller's scope. Closing the scope closes sockets and
 * frees the port, then awaits request fibers, then closes SQLite, then removes a
 * temporary directory.
 */
const makeWorkspace = Effect.fnUntraced(function* (options: DisposableIssuerOptions) {
  const fs = yield* FileSystem.FileSystem;
  const staticRoot = fileURLToPath(new URL("./web/", import.meta.url));

  if (!(yield* fs.exists(join(staticRoot, "index.html"))))
    return yield* Effect.fail(
      new Error(
        "The @gjermundgaraba/clankerauth-dev installation is missing its bundled dashboard assets",
      ),
    );
  const dataDir = options.dataDir;

  const directory =
    dataDir === undefined
      ? yield* fs.makeTempDirectoryScoped({ prefix: "clankerauth-disposable-" })
      : yield* Effect.as(
          fs.makeDirectory(resolve(dataDir), { recursive: true, mode: 0o700 }),
          resolve(dataDir),
        );

  // why: listen first, as the issuer's URL needs the port
  const listener = yield* listen(options.port ?? 0, "127.0.0.1");
  const { port } = listener;

  // why: a cookie shared across hosts needs a common parent domain, which an IP address lacks.
  const url =
    options.cookieDomain === undefined
      ? `http://127.0.0.1:${port}`
      : `http://clankerauth.${options.cookieDomain}:${port}`;

  const identity = yield* loadIdentity(directory, dataDir !== undefined);

  const settings = yield* validateSettings({
    baseURL: url,
    secret: Redacted.make(identity.secret),
    database: join(directory, "issuer.sqlite"),
    host: "127.0.0.1",
    port,
    mcpAllowedOrigins: [],
    trustProxy: false,
    allowInsecureHttp: options.cookieDomain !== undefined,
    cookieDomain: options.cookieDomain,
  });

  const issuer = yield* Layer.build(
    issuerServices(
      Layer.succeed(Settings, settings),
      CimdTransport.layerWith(options.cimdTransport),
    ),
  );

  const account = Context.get(issuer, OwnerAccount);
  const catalog = Context.get(issuer, ResourceCatalog);

  const requests = yield* Scope.fork(yield* Effect.scope);

  const handler = yield* nodeHandler(staticRoot).pipe(
    Effect.provide(issuer),
    Effect.provideService(Scope.Scope, requests),
  );

  yield* listener.serve((incoming, outgoing) => {
    try {
      options.onRequest?.({
        method: incoming.method ?? "GET",
        url: new URL(incoming.url ?? "/", `http://127.0.0.1:${incoming.socket.localPort}`),
      });
      handler(incoming, outgoing);
    } catch {
      if (outgoing.headersSent) outgoing.destroy();
      else outgoing.writeHead(500).end("Request failed");
    }
  });

  const owner = { email: identity.email, password: identity.password };

  const clients = Context.get(issuer, Clients);
  const resources = Context.get(issuer, Resources);
  const keys = Context.get(issuer, ApiKeys);

  /**
   * Run administration as the owner, the way the dashboard's session does. No code path
   * detaches a provider Promise: like a request handler, this runs uninterruptibly, so
   * `close()` during a call waits for it and its session cleanup before SQLite closes.
   */
  const asOwner = <A, E>(
    operation: (userId: string) => Effect.Effect<A, E, CurrentOwner | Scope.Scope>,
  ) =>
    Effect.uninterruptible(
      Effect.scoped(
        Effect.gen(function* () {
          const userId = yield* account.find();

          if (userId === undefined) return yield* Effect.die(new Error("Owner setup failed"));

          return yield* operation(userId).pipe(
            Effect.provideService(CurrentOwner, account.caller(userId, owner.email, true)),
          );
        }),
      ),
    ).pipe(Effect.mapError(provisioningFailed));

  if (!(yield* account.find()))
    yield* account.create(owner).pipe(Effect.mapError(provisioningFailed));

  yield* asOwner(() =>
    Effect.forEach(options.resources, (resource) =>
      Effect.flatMap(catalog.get(resource.identifier), (existing) =>
        existing ? Effect.void : Effect.asVoid(resources.create(resource)),
      ),
    ),
  );

  const registered = yield* asOwner(() =>
    Effect.gen(function* () {
      if (identity.clientId !== undefined && identity.clientSecret !== undefined) {
        const { clients: known } = yield* clients.list();

        if (known.some((client) => client.client_id === identity.clientId))
          return { client_id: identity.clientId, client_secret: identity.clientSecret };
      }

      return yield* clients.create({
        client_name: options.client.name,
        redirect_uris: [options.client.redirect],
        resources: options.client.resources,
        token_endpoint_auth_method: "client_secret_basic",
        application_type: "native",
      });
    }),
  );

  const clientSecret = registered.client_secret;

  if (clientSecret === undefined)
    return yield* Effect.fail(new Error("Disposable issuer did not return client credentials"));

  if (dataDir !== undefined)
    yield* saveIdentity(directory, {
      ...identity,
      clientId: registered.client_id,
      clientSecret,
    });

  const forwardOrigin = options.cookieDomain === undefined ? undefined : url;

  return {
    details: {
      issuer: `${url}/api/auth`,
      clientId: registered.client_id,
      clientSecret,
      owner,
      url,
      port,
      directory,
    },
    apiKey: (input: { readonly name?: string; readonly permissions: Record<string, string[]> }) =>
      asOwner(() =>
        Effect.map(
          keys.create({
            name: input.name ?? "development",
            permissions: input.permissions,
            expiresAt: null,
          }),
          (created) => created.key,
        ),
      ),
    ownerSession: (appOrigin: string) => ownerSession(url, forwardOrigin, owner, appOrigin),
    ownerToken: Effect.fn("Dev.ownerToken")(function* (input: {
      readonly resource: string;
      readonly appOrigin: string;
    }) {
      const { cookie } = yield* ownerSession(url, forwardOrigin, owner, input.appOrigin);
      const client = yield* HttpClient.HttpClient;
      const app = new URL(input.appOrigin);
      const check = new URL("/forward-auth", url);
      check.searchParams.set("resource", input.resource);

      const decision = yield* client.get(check, {
        headers: {
          cookie,
          "x-forwarded-proto": app.protocol.slice(0, -1),
          "x-forwarded-host": app.host,
          "x-forwarded-uri": "/",
        },
      });

      yield* decision.text;
      const authorization = decision.headers.authorization;

      if (decision.status !== 204 || authorization === undefined)
        return yield* Effect.fail(
          new Error(`Forward auth issued no token (HTTP ${decision.status})`),
        );

      return authorization.replace(/^Bearer /iu, "");
    }),
  };
});

/** Start an issuer on a loopback port. The caller owns signals; `close()` waits for calls in flight. */
export async function startDisposableIssuer(
  options: DisposableIssuerOptions,
): Promise<DisposableIssuer> {
  const scope = Scope.makeUnsafe();

  // why: fibers join the scope, so `close()` interrupts a call in flight before SQLite closes.
  const run = <A, E>(effect: Effect.Effect<A, E, Layer.Success<typeof platform> | Scope.Scope>) =>
    Effect.runPromise(
      effect.pipe(Effect.provideService(Scope.Scope, scope), Effect.provide(platform)),
      { onFiberStart: Fiber.runIn(scope) },
    );

  const dispose = Effect.runSync(Effect.cached(Scope.close(scope, Exit.void)));

  try {
    const workspace = await run(makeWorkspace(options));

    return {
      ...workspace.details,
      apiKey: (input) => run(workspace.apiKey(input)),
      ownerSession: (appOrigin) => run(workspace.ownerSession(appOrigin)),
      ownerToken: (input) => run(workspace.ownerToken(input)),
      close: () => Effect.runPromise(dispose),
    };
  } catch (error) {
    await Effect.runPromise(dispose);
    throw error;
  }
}
