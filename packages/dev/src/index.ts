import { randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ApiKeys,
  CimdTransport,
  Clients,
  issuerServices,
  listen,
  nodeHandler,
  OwnerAccount,
  Resources,
  Settings,
  validateSettings,
} from "@clankerauth/server/embed";
import { NodeFileSystem } from "@effect/platform-node";
import {
  CurrentOwner,
  ResourceInput,
} from "@gjermundgaraba/clankerauth-admin-api";
import {
  Context,
  Data,
  Effect,
  Exit,
  Fiber,
  FileSystem,
  Layer,
  Redacted,
  Schema,
  Scope,
} from "effect";
import {
  Cookies,
  FetchHttpClient,
  HttpClient,
  HttpClientRequest,
} from "effect/http";

import type {
  DisposableIssuer,
  DisposableIssuerOptions,
  Identity,
} from "./types.d.ts";

const credentialsFile = "credentials.json";

const IdentityFile = Schema.Struct({
  email: Schema.String,
  password: Schema.String,
  secret: Schema.String,
  clientId: Schema.optional(Schema.String),
  clientSecret: Schema.optional(Schema.String),
});

const decodeIdentity = Schema.decodeUnknownEffect(
  Schema.fromJsonString(IdentityFile)
);

const encodeIdentity = Schema.encodeSync(IdentityFile);

const saveIdentity = (directory: string, identity: Identity) =>
  Effect.flatMap(FileSystem.FileSystem, (fs) =>
    fs.writeFileString(
      path.join(directory, credentialsFile),
      `${JSON.stringify(encodeIdentity(identity), null, 2)}\n`,
      { mode: 0o600 }
    )
  );

const loadIdentity = Effect.fn("Dev.identity")(function* (
  directory: string,
  persistent: boolean
) {
  const fresh: Identity = {
    email: "owner@example.internal",
    password: randomBytes(24).toString("base64url"),
    secret: randomBytes(32).toString("hex"),
  };

  if (!persistent) {
    return fresh;
  }

  const fs = yield* FileSystem.FileSystem;
  const file = path.join(directory, credentialsFile);

  if (yield* fs.exists(file)) {
    return yield* decodeIdentity(yield* fs.readFileString(file));
  }

  yield* saveIdentity(directory, fresh);

  return fresh;
});

export class ProvisioningError extends Data.TaggedError("ProvisioningError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

export class ForwardAuthError extends Data.TaggedError("ForwardAuthError")<{
  readonly message: string;
}> {}

const provisioningFailed = (cause: unknown) =>
  new ProvisioningError({
    message: "Disposable issuer provisioning failed",
    cause,
  });

const decodeResources = Schema.decodeEffect(Schema.Array(ResourceInput));

const ownerSession = Effect.fn("Dev.ownerSession")(function* (
  issuerUrl: string,
  forwardOrigin: string | undefined,
  owner: { readonly email: string; readonly password: string },
  appOrigin: string
) {
  if (forwardOrigin === undefined) {
    return yield* new ForwardAuthError({
      message:
        "A forward-auth session needs a cookieDomain; the issuer serves none",
    });
  }

  const client = yield* HttpClient.HttpClient;

  const signIn = yield* client.execute(
    HttpClientRequest.post(`${issuerUrl}/api/auth/sign-in/email`, {
      headers: { origin: issuerUrl },
    }).pipe(HttpClientRequest.bodyJsonUnsafe(owner))
  );

  yield* signIn.text;

  if (signIn.status !== 200) {
    return yield* new ForwardAuthError({
      message: `Owner sign-in failed with HTTP ${signIn.status}`,
    });
  }

  const destination = new URL("/", appOrigin).href;

  const sealed = yield* client.get(
    `${issuerUrl}/forward-auth/continue?rd=${encodeURIComponent(destination)}`,
    { headers: { cookie: Cookies.toCookieHeader(signIn.cookies) } }
  );

  yield* sealed.text;
  const jar = Cookies.merge(signIn.cookies, sealed.cookies);

  return {
    cookie: Cookies.toCookieHeader(jar),
    cookies: Object.entries(Cookies.toRecord(jar)).map(([name, value]) => ({
      name,
      value,
    })),
  };
});

const platform = Layer.mergeAll(
  NodeFileSystem.layer,
  FetchHttpClient.layer,
  Layer.succeed(FetchHttpClient.RequestInit, { redirect: "manual" })
);

const makeWorkspace = Effect.fnUntraced(function* (
  options: DisposableIssuerOptions
) {
  const declared = yield* decodeResources(options.resources).pipe(
    Effect.mapError(provisioningFailed)
  );

  const fs = yield* FileSystem.FileSystem;
  const staticRoot = fileURLToPath(new URL("web/", import.meta.url));

  if (!(yield* fs.exists(path.join(staticRoot, "index.html")))) {
    return yield* new ProvisioningError({
      message:
        "The @gjermundgaraba/clankerauth-dev installation is missing its bundled dashboard assets",
    });
  }

  const { dataDir } = options;

  const directory =
    dataDir === undefined
      ? yield* fs.makeTempDirectoryScoped({ prefix: "clankerauth-disposable-" })
      : yield* Effect.as(
          fs.makeDirectory(path.resolve(dataDir), {
            recursive: true,
            mode: 0o700,
          }),
          path.resolve(dataDir)
        );

  const listener = yield* listen(options.port ?? 0, "127.0.0.1");
  const { port } = listener;

  const url =
    options.cookieDomain === undefined
      ? `http://127.0.0.1:${port}`
      : `http://clankerauth.${options.cookieDomain}:${port}`;

  const identity = yield* loadIdentity(directory, dataDir !== undefined);

  const settings = yield* validateSettings({
    baseURL: url,
    secret: Redacted.make(identity.secret),
    database: path.join(directory, "issuer.sqlite"),
    host: "127.0.0.1",
    port,
    mcpAllowedOrigins: [],
    trustProxy: false,
    allowInsecureHttp: options.cookieDomain !== undefined,
    cookieDomain: options.cookieDomain,
  }).pipe(Effect.mapError(({ message }) => new ProvisioningError({ message })));

  const issuer = yield* Layer.build(
    issuerServices(
      Layer.succeed(Settings, settings),
      CimdTransport.layerWith(options.cimdTransport)
    )
  ).pipe(
    Effect.catchTag("SchemaRepairRequired", ({ message }) =>
      Effect.fail(new ProvisioningError({ message }))
    )
  );

  const account = Context.get(issuer, OwnerAccount);

  const requests = yield* Scope.fork(yield* Effect.scope);

  const handler = yield* nodeHandler(staticRoot).pipe(
    Effect.provide(issuer),
    Effect.provideService(Scope.Scope, requests)
  );

  yield* listener.serve((incoming, outgoing) => {
    try {
      options.onRequest?.({
        method: incoming.method ?? "GET",
        url: new URL(
          incoming.url ?? "/",
          `http://127.0.0.1:${incoming.socket.localPort}`
        ),
      });
      handler(incoming, outgoing);
    } catch {
      if (outgoing.headersSent) {
        outgoing.destroy();
      } else {
        outgoing.writeHead(500).end("Request failed");
      }
    }
  });

  const owner = { email: identity.email, password: identity.password };

  const clients = Context.get(issuer, Clients);
  const resources = Context.get(issuer, Resources);
  const keys = Context.get(issuer, ApiKeys);

  const asOwner = <A, E>(
    operation: (
      userId: string
    ) => Effect.Effect<A, E, CurrentOwner | Scope.Scope>
  ) =>
    Effect.uninterruptible(
      Effect.scoped(
        Effect.gen(function* () {
          const userId = yield* account.find;

          if (userId === undefined) {
            return yield* Effect.die(new Error("Owner setup failed"));
          }

          return yield* operation(userId).pipe(
            Effect.provideService(
              CurrentOwner,
              account.caller(userId, owner.email, true)
            )
          );
        })
      )
    ).pipe(Effect.mapError(provisioningFailed));

  if ((yield* account.find) === undefined) {
    yield* account.create(owner).pipe(Effect.mapError(provisioningFailed));
  }

  yield* asOwner(() =>
    Effect.forEach(declared, (resource) => resources.put(resource), {
      discard: true,
    })
  );

  const registered = yield* asOwner(() =>
    Effect.gen(function* () {
      if (
        identity.clientId !== undefined &&
        identity.clientSecret !== undefined
      ) {
        const { clients: known } = yield* clients.list;

        if (known.some((client) => client.client_id === identity.clientId)) {
          return {
            client_id: identity.clientId,
            client_secret: identity.clientSecret,
          };
        }
      }

      return yield* clients.create({
        client_name: options.client.name,
        redirect_uris: [options.client.redirect],
        resources: options.client.resources,
        token_endpoint_auth_method: "client_secret_basic",
        application_type: "native",
      });
    })
  );

  const clientSecret = registered.client_secret;

  if (clientSecret === undefined) {
    return yield* new ProvisioningError({
      message: "Disposable issuer did not return client credentials",
    });
  }

  if (dataDir !== undefined) {
    yield* saveIdentity(directory, {
      ...identity,
      clientId: registered.client_id,
      clientSecret,
    });
  }

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
    apiKey: (input: {
      readonly name?: string;
      readonly permissions: Record<string, string[]>;
    }) =>
      asOwner(() =>
        Effect.map(
          keys.create({
            name: input.name ?? "development",
            permissions: input.permissions,
            expiresAt: null,
          }),
          (created) => created.key
        )
      ),
    ownerSession: (appOrigin: string) =>
      ownerSession(url, forwardOrigin, owner, appOrigin),
    ownerToken: Effect.fn("Dev.ownerToken")(function* (input: {
      readonly resource: string;
      readonly appOrigin: string;
    }) {
      const { cookie } = yield* ownerSession(
        url,
        forwardOrigin,
        owner,
        input.appOrigin
      );

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
      const { authorization } = decision.headers;

      if (decision.status !== 204 || authorization === undefined) {
        return yield* new ForwardAuthError({
          message: `Forward auth issued no token (HTTP ${decision.status})`,
        });
      }

      return authorization.replace(/^Bearer /iu, "");
    }),
  };
});

export const startDisposableIssuer = async (
  options: DisposableIssuerOptions
): Promise<DisposableIssuer> => {
  const scope = Scope.makeUnsafe();

  const run = async <A, E>(
    effect: Effect.Effect<A, E, Layer.Success<typeof platform> | Scope.Scope>
  ) =>
    await Effect.runPromise(
      effect.pipe(
        Effect.provideService(Scope.Scope, scope),
        Effect.provide(platform)
      ),
      {
        onFiberStart: (fiber) => {
          Fiber.runIn(fiber, scope);
        },
      }
    );

  const dispose = Effect.runSync(Effect.cached(Scope.close(scope, Exit.void)));

  try {
    const workspace = await run(makeWorkspace(options));

    return {
      ...workspace.details,
      apiKey: async (input) => await run(workspace.apiKey(input)),
      ownerSession: async (appOrigin) =>
        await run(workspace.ownerSession(appOrigin)),
      ownerToken: async (input) => await run(workspace.ownerToken(input)),
      close: async () => {
        await Effect.runPromise(dispose);
      },
    };
  } catch (error) {
    await Effect.runPromise(dispose);
    throw error;
  }
};
