import { randomBytes } from "node:crypto";
import { access, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { application } from "../../../apps/server/src/app.ts";
import { initialize, openAuth } from "../../../apps/server/src/auth.ts";

/**
 * Start a real, isolated issuer for one development run. The caller owns signals and must await close() on shutdown.
 * @param {{resources: Array<{identifier: string, name: string, scopes: string[]}>, client: {name: string, redirect: string, resources: string[]}}} options
 */
export async function startDisposableIssuer({ resources, client }) {
  const staticRoot = fileURLToPath(new URL("./web/", import.meta.url));
  await access(join(staticRoot, "index.html")).catch(() => {
    throw new Error("The @clankerauth/dev installation is missing its bundled dashboard assets");
  });
  const directory = await mkdtemp(join(tmpdir(), "clankerauth-disposable-"));
  let service;
  let handler;
  let url;
  let closing;
  const active = new Set();
  const serve = async (incoming, outgoing) => {
    try {
      if (!incoming.url?.startsWith("/") || incoming.url.startsWith("//")) {
        outgoing.writeHead(400).end();
        return;
      }
      if (!handler) {
        outgoing.writeHead(503).end();
        return;
      }
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (
          value &&
          !["forwarded", "x-forwarded-host", "x-forwarded-proto", "x-clankerauth-peer"].includes(
            name,
          )
        ) {
          headers.set(name, Array.isArray(value) ? value.join(", ") : value);
        }
      }
      headers.set("x-clankerauth-peer", incoming.socket.remoteAddress ?? "unknown");
      const chunks = [];
      let size = 0;
      for await (const chunk of incoming) {
        size += chunk.length;
        if (size > 65536) {
          outgoing.writeHead(413).end();
          return;
        }
        chunks.push(chunk);
      }
      const response = await handler(
        new Request(`${url}${incoming.url}`, {
          method: incoming.method,
          headers,
          body: ["GET", "HEAD"].includes(incoming.method) ? undefined : Buffer.concat(chunks),
        }),
      );
      outgoing.writeHead(response.status, {
        ...Object.fromEntries(response.headers),
        "set-cookie": response.headers.getSetCookie(),
      });
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      if (!outgoing.headersSent) outgoing.writeHead(500);
      outgoing.end();
    }
  };
  const server = createServer((incoming, outgoing) => {
    const request = serve(incoming, outgoing);
    active.add(request);
    void request.finally(() => active.delete(request));
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  const close = () =>
    (closing ??= (async () => {
      try {
        await new Promise((resolve, reject) => {
          server.close((error) =>
            error && error.code !== "ERR_SERVER_NOT_RUNNING" ? reject(error) : resolve(),
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
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    const port = server.address().port;
    url = `http://127.0.0.1:${port}`;
    service = await openAuth({
      baseURL: url,
      secret: randomBytes(32).toString("hex"),
      database: join(directory, "issuer.sqlite"),
      host: "127.0.0.1",
      port,
    });
    await initialize(service);
    handler = application(service, staticRoot);
    const owner = {
      email: "owner@example.internal",
      password: randomBytes(24).toString("base64url"),
    };
    const cookies = new Map();
    const post = async (path, body, status) => {
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
        const pair = cookie.split(";")[0];
        const separator = pair.indexOf("=");
        cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
      }
      return response.json();
    };
    await post("/api/setup", owner, 201);
    await post("/api/auth/sign-in/email", owner, 200);
    for (const resource of resources) await post("/admin/resources", resource, 201);
    const registration = await post(
      "/admin/clients",
      { ...client, confidential: true, native: true },
      201,
    );
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
