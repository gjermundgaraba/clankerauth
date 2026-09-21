import { randomBytes } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Redacted, Effect, Exit, Scope } from "effect";
import { administration } from "../../../apps/server/src/administration.ts";
import { nodeHandler } from "../../../apps/server/src/app.ts";
import { createOwner, initialize, openAuth, type Service } from "../../../apps/server/src/auth.ts";
import { validateSettings } from "../../../apps/server/src/config.ts";
import { CurrentOwner } from "../../../apps/server/src/current-owner.ts";
import { machineKeys } from "../../../apps/server/src/machine-keys.ts";
import { providerSession } from "../../../apps/server/src/provider-session.ts";
import { createNodeServer } from "../../../apps/server/src/node-http.ts";
import type { DisposableIssuer, DisposableIssuerOptions, Identity } from "./types.d.ts";

const credentialsFile = "credentials.json";

/**
 * A run's identity. A disposable issuer invents one; a persistent workspace keeps it
 * in its data directory, so the owner account, the signing secret and the registered
 * client survive a restart. The file is the whole secret: it is the workspace.
 */
const loadIdentity = async (directory: string, persistent: boolean): Promise<Identity> => {
  const fresh: Identity = {
    email: "owner@example.internal",
    password: randomBytes(24).toString("base64url"),
    secret: randomBytes(32).toString("hex"),
  };

  if (!persistent) return fresh;
  const path = join(directory, credentialsFile);
  const existing = await readFile(path, "utf8").catch(() => undefined);

  if (existing !== undefined) {
    // SAFETY: this file is written by `saveIdentity` below and lives in the caller's
    // own data directory; a hand-edited one fails at the first use of a missing field.
    return JSON.parse(existing) as Identity;
  }

  await writeFile(path, `${JSON.stringify(fresh, null, 2)}\n`, { mode: 0o600 });

  return fresh;
};

const saveIdentity = (directory: string, identity: Identity) =>
  writeFile(join(directory, credentialsFile), `${JSON.stringify(identity, null, 2)}\n`, {
    mode: 0o600,
  });

/** Start an issuer on a loopback port. The caller owns signals and must await close(). */
export async function startDisposableIssuer({
  resources,
  client,
  cookieDomain,
  cimdTransport,
  onRequest,
  dataDir,
  port: requestedPort = 0,
}: DisposableIssuerOptions): Promise<DisposableIssuer> {
  const staticRoot = fileURLToPath(new URL("./web/", import.meta.url));
  await access(join(staticRoot, "index.html")).catch(() => {
    throw new Error(
      "The @gjermundgaraba/clankerauth-dev installation is missing its bundled dashboard assets",
    );
  });
  const persistent = dataDir !== undefined;

  if (persistent) await mkdir(dataDir, { recursive: true, mode: 0o700 });

  const directory = persistent
    ? resolve(dataDir)
    : await mkdtemp(join(tmpdir(), "clankerauth-disposable-"));

  let service: Service | undefined;
  let httpScope: Scope.Closeable | undefined;
  let closing: Promise<void> | undefined;

  // Listen first to discover the port; reject requests until initialization completes.
  let serve = (_incoming: IncomingMessage, outgoing: ServerResponse) => {
    outgoing.writeHead(503).end();
  };

  const server = createNodeServer((incoming, outgoing) => {
    try {
      onRequest?.({
        method: incoming.method ?? "GET",
        url: new URL(incoming.url ?? "/", `http://127.0.0.1:${incoming.socket.localPort}`),
      });
      serve(incoming, outgoing);
    } catch {
      if (outgoing.headersSent) outgoing.destroy();
      else outgoing.writeHead(500).end("Request failed");
    }
  });

  const close = () =>
    (closing ??= (async () => {
      try {
        const stopped = new Promise<void>((resolve, reject) => {
          server.close((error) =>
            error && (!("code" in error) || error.code !== "ERR_SERVER_NOT_RUNNING")
              ? reject(error)
              : resolve(),
          );
          // Also release incomplete uploads and connections without a request fiber.
          server.closeAllConnections();
        });

        // Interrupt response delivery without abandoning tracked provider work.
        await Promise.all([
          stopped,
          httpScope ? Effect.runPromise(Scope.close(httpScope, Exit.void)) : Promise.resolve(),
        ]);
      } finally {
        try {
          await service?.close();
        } finally {
          // A workspace directory belongs to its caller; only a temporary one is removed.
          if (!persistent) await rm(directory, { recursive: true, force: true });
        }
      }
    })());

  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(requestedPort, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    const address = server.address();

    if (!(address instanceof Object))
      throw new Error("Disposable issuer failed to bind a TCP port");

    const { port } = address;

    // Forward auth shares a cookie across hosts, which an IP address cannot do. A `.localhost`
    // name resolves to this loopback listener and gives the issuer and the apps a common parent.
    const url =
      cookieDomain === undefined
        ? `http://127.0.0.1:${port}`
        : `http://auth.${cookieDomain}:${port}`;

    const identity = await loadIdentity(directory, persistent);

    service = await Effect.runPromise(
      openAuth(
        validateSettings({
          baseURL: url,
          secret: Redacted.make(identity.secret),
          database: join(directory, "issuer.sqlite"),
          host: "127.0.0.1",
          port,
          trustProxy: false,
          allowInsecureHttp: cookieDomain !== undefined,
          cookieDomain,
        }),
        { cimdTransport },
      ),
    );
    await Effect.runPromise(initialize(service));
    httpScope = Scope.makeUnsafe();
    serve = await Effect.runPromise(
      nodeHandler(service, staticRoot).pipe(Effect.provideService(Scope.Scope, httpScope)),
    );

    const owner = { email: identity.email, password: identity.password };

    // Seed in-process: the owner's provider session authorizes administration directly.
    const issuer = service;
    const admin = administration(issuer);
    const keys = machineKeys(issuer);

    /** Run administration as the owner, the way the dashboard's session does. */
    const asOwner = <A, E>(
      operation: (userId: string) => Effect.Effect<A, E, CurrentOwner | Scope.Scope>,
    ) =>
      Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const userId = yield* issuer.owner();

            if (userId === undefined) return yield* Effect.die(new Error("Owner setup failed"));
            const headers = yield* providerSession(issuer, userId);

            return yield* operation(userId).pipe(
              Effect.provideService(CurrentOwner, {
                userId,
                email: owner.email,
                providerHeaders: Effect.succeed(headers),
              }),
            );
          }),
        ).pipe(
          Effect.mapError(
            (error) => new Error("Disposable issuer provisioning failed", { cause: error }),
          ),
        ),
      );

    // Every step is idempotent, so a persistent workspace restarts onto its own state.
    if (!(await Effect.runPromise(issuer.owner())))
      await Effect.runPromise(
        Effect.scoped(createOwner(issuer, owner)).pipe(
          Effect.mapError(
            (error) => new Error("Disposable issuer provisioning failed", { cause: error }),
          ),
        ),
      );

    await asOwner(() =>
      Effect.forEach(resources, (resource) =>
        Effect.flatMap(issuer.resources.get(resource.identifier), (existing) =>
          existing ? Effect.void : Effect.asVoid(admin.createResource(resource)),
        ),
      ),
    );

    const registered = await asOwner(() =>
      Effect.gen(function* () {
        if (identity.clientId !== undefined && identity.clientSecret !== undefined) {
          const { clients } = yield* admin.list();

          if (clients.some((known) => known.client_id === identity.clientId))
            return { client_id: identity.clientId, client_secret: identity.clientSecret };
        }

        return yield* admin.create({
          client_name: client.name,
          redirect_uris: [client.redirect],
          resources: client.resources,
          token_endpoint_auth_method: "client_secret_basic",
          application_type: "native",
        });
      }),
    );

    if (registered.client_secret === undefined)
      throw new Error("Disposable issuer did not return client credentials");

    if (persistent)
      await saveIdentity(directory, {
        ...identity,
        clientId: registered.client_id,
        clientSecret: registered.client_secret,
      });

    const forwardOrigin = cookieDomain === undefined ? undefined : url;

    return {
      issuer: `${url}/api/auth`,
      clientId: registered.client_id,
      clientSecret: registered.client_secret,
      owner,
      url,
      port,
      directory,
      apiKey: (input) =>
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
      ownerSession: (appOrigin) => ownerSession(url, forwardOrigin, owner, appOrigin),
      ownerToken: async (input) => {
        const { cookie } = await ownerSession(url, forwardOrigin, owner, input.appOrigin);
        const app = new URL(input.appOrigin);
        const check = new URL("/forward-auth", url);
        check.searchParams.set("resource", input.resource);

        const decision = await fetch(check, {
          redirect: "manual",
          headers: {
            cookie,
            "x-forwarded-proto": app.protocol.slice(0, -1),
            "x-forwarded-host": app.host,
            "x-forwarded-uri": "/",
          },
        });

        const authorization = decision.headers.get("authorization");
        await decision.body?.cancel().catch(() => {});

        if (decision.status !== 204 || authorization === null)
          throw new Error(`Forward auth issued no token (HTTP ${decision.status})`);

        return authorization.replace(/^Bearer /iu, "");
      },
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}

/** Sign the owner in and seal the forward cookie, the way a browser does. */
const ownerSession = async (
  issuerUrl: string,
  forwardOrigin: string | undefined,
  owner: { readonly email: string; readonly password: string },
  appOrigin: string,
) => {
  if (forwardOrigin === undefined)
    throw new Error("A forward-auth session needs a cookieDomain; the issuer serves none");
  const jar = new Map<string, string>();

  const collect = async (response: Response) => {
    for (const raw of response.headers.getSetCookie()) {
      const end = raw.indexOf(";");
      const pair = end === -1 ? raw : raw.slice(0, end);
      const separator = pair.indexOf("=");

      if (separator > 0) jar.set(pair.slice(0, separator), pair.slice(separator + 1));
    }

    await response.body?.cancel().catch(() => {});

    return response;
  };

  const cookie = () => [...jar].map(([name, value]) => `${name}=${value}`).join("; ");

  const signIn = await fetch(`${issuerUrl}/api/auth/sign-in/email`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", origin: issuerUrl },
    body: JSON.stringify(owner),
  });

  if (!signIn.ok) {
    await signIn.body?.cancel().catch(() => {});
    throw new Error(`Owner sign-in failed with HTTP ${signIn.status}`);
  }

  await collect(signIn);
  // `/forward-auth/continue` seals the session into the cookie the domain shares.
  const destination = new URL("/", appOrigin).href;

  await collect(
    await fetch(`${issuerUrl}/forward-auth/continue?rd=${encodeURIComponent(destination)}`, {
      redirect: "manual",
      headers: { cookie: cookie() },
    }),
  );

  return {
    cookie: cookie(),
    cookies: [...jar].map(([name, value]) => ({ name, value })),
  };
};
