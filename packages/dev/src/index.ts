import { randomBytes } from "node:crypto";
import { access, mkdtemp, rm } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Redacted, Effect, Exit, Scope } from "effect";
import { administration } from "../../../apps/server/src/administration.ts";
import { nodeHandler } from "../../../apps/server/src/app.ts";
import { createOwner, initialize, openAuth, type Service } from "../../../apps/server/src/auth.ts";
import { CurrentOwner } from "../../../apps/server/src/current-owner.ts";
import { providerSession } from "../../../apps/server/src/provider-session.ts";
import { createNodeServer } from "../../../apps/server/src/node-http.ts";
import type { DisposableIssuer, DisposableIssuerOptions } from "./types.d.ts";

/** Start a fresh issuer on a random loopback port. The caller owns signals and must await close(). */
export async function startDisposableIssuer({
  resources,
  client,
  cimdTransport,
  onRequest,
}: DisposableIssuerOptions): Promise<DisposableIssuer> {
  const staticRoot = fileURLToPath(new URL("./web/", import.meta.url));
  await access(join(staticRoot, "index.html")).catch(() => {
    throw new Error(
      "The @gjermundgaraba/clankerauth-dev installation is missing its bundled dashboard assets",
    );
  });
  const directory = await mkdtemp(join(tmpdir(), "clankerauth-disposable-"));
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
          await rm(directory, { recursive: true, force: true });
        }
      }
    })());

  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    const address = server.address();

    if (!(address instanceof Object))
      throw new Error("Disposable issuer failed to bind a TCP port");

    const { port } = address;
    const url = `http://127.0.0.1:${port}`;
    service = await Effect.runPromise(
      openAuth(
        {
          baseURL: url,
          secret: Redacted.make(randomBytes(32).toString("hex")),
          database: join(directory, "issuer.sqlite"),
          host: "127.0.0.1",
          port,
        },
        { cimdTransport },
      ),
    );
    await Effect.runPromise(initialize(service));
    httpScope = Scope.makeUnsafe();
    serve = await Effect.runPromise(
      nodeHandler(service, staticRoot).pipe(Effect.provideService(Scope.Scope, httpScope)),
    );

    const owner = {
      email: "owner@example.internal",
      password: randomBytes(24).toString("base64url"),
    };

    // Seed in-process: the owner's provider session authorizes administration directly.
    const issuer = service;
    const admin = administration(issuer);

    const registration = await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          yield* createOwner(issuer, owner);
          const userId = yield* issuer.owner();

          if (userId === undefined) return yield* Effect.die(new Error("Owner setup failed"));
          const headers = yield* providerSession(issuer, userId);

          return yield* Effect.gen(function* () {
            for (const resource of resources) yield* admin.createResource(resource);

            return yield* admin.create({ ...client, confidential: true, native: true });
          }).pipe(
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

    if (registration.client_secret === undefined)
      throw new Error("Disposable issuer did not return client credentials");

    return {
      issuer: `${url}/api/auth`,
      clientId: registration.client_id,
      clientSecret: registration.client_secret,
      owner,
      url,
      directory,
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
