import { randomBytes } from "node:crypto";
import { access, mkdtemp, rm } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { application } from "../../../apps/server/src/app.ts";
import { initialize, openAuth, type Service } from "../../../apps/server/src/auth.ts";
import { createNodeServer, nodeListener } from "../../../apps/server/src/node-http.ts";
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
  let handler: ReturnType<typeof application> | undefined;
  let closing: Promise<void> | undefined;
  const active = new Set<Promise<void>>();
  // Listen first to discover the port; reject requests until initialization completes.
  let serve = async (_incoming: IncomingMessage, outgoing: ServerResponse) => {
    outgoing.writeHead(503).end();
  };
  const server = createNodeServer((incoming, outgoing) => {
    const request = (async () => {
      try {
        onRequest?.({
          method: incoming.method ?? "GET",
          url: new URL(incoming.url ?? "/", `http://127.0.0.1:${incoming.socket.localPort}`),
        });
        await serve(incoming, outgoing);
      } catch {
        if (outgoing.headersSent) outgoing.destroy();
        else outgoing.writeHead(500).end("Request failed");
      }
    })();
    active.add(request);
    void request.finally(() => active.delete(request));
  });
  const close = () =>
    (closing ??= (async () => {
      try {
        await new Promise<void>((resolve, reject) => {
          server.close((error) =>
            error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING"
              ? reject(error)
              : resolve(),
          );
          server.closeIdleConnections();
        });
        await Promise.allSettled(active);
      } finally {
        try {
          await handler?.dispose();
        } finally {
          try {
            await service?.close();
          } finally {
            await rm(directory, { recursive: true, force: true });
          }
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
    const { port } = server.address() as AddressInfo;
    const url = `http://127.0.0.1:${port}`;
    service = await openAuth(
      {
        baseURL: url,
        secret: randomBytes(32).toString("hex"),
        database: join(directory, "issuer.sqlite"),
        host: "127.0.0.1",
        port,
      },
      { cimdTransport },
    );
    await initialize(service);
    handler = application(service, staticRoot);
    serve = nodeListener(handler, url);
    const owner = {
      email: "owner@example.internal",
      password: randomBytes(24).toString("base64url"),
    };
    const cookies = new Map<string, string>();
    const post = async (path: string, body: unknown, status: number): Promise<unknown> => {
      const response = await fetch(new URL(path, url), {
        method: "POST",
        redirect: "manual",
        signal: AbortSignal.timeout(15000),
        headers: {
          origin: url,
          cookie: [...cookies].map(([name, value]) => `${name}=${value}`).join("; "),
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      });
      if (response.status !== status) {
        await response.body?.cancel();
        throw new Error(`Disposable issuer provisioning failed at ${path} (${response.status})`);
      }
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(";")[0]!;
        const separator = pair.indexOf("=");
        cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
      }
      return response.json();
    };
    await post("/api/setupOwner", owner, 201);
    await post("/api/auth/sign-in/email", owner, 200);
    for (const resource of resources) await post("/api/createResource", resource, 201);
    const registration = (await post(
      "/api/createClient",
      { ...client, confidential: true, native: true },
      201,
    )) as { client_id: string; client_secret?: string };
    if (!registration.client_secret)
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
