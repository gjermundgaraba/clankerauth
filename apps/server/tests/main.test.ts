import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test, vi } from "vite-plus/test";

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function reservePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();

  if (address === null || !(address instanceof Object)) throw new Error("Expected TCP address");

  const close = () =>
    new Promise<void>((resolve, reject) => {
      if (!server.listening) return resolve();
      server.close((error) => (error ? reject(error) : resolve()));
    });

  cleanups.push(close);

  return { port: address.port, close };
}

function start(port: number) {
  const directory = mkdtempSync(join(tmpdir(), "clankerauth-main-"));
  const database = join(directory, "clankerauth.sqlite");
  const url = `http://127.0.0.1:${port}`;

  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL("../src/main.ts", import.meta.url))],
    {
      cwd: directory,
      env: {
        ...process.env,
        CLANKERAUTH_BASE_URL: url,
        CLANKERAUTH_BETTER_AUTH_SECRET: "test-only-secret-with-at-least-32-characters",
        CLANKERAUTH_DATABASE: database,
        CLANKERAUTH_HOST: "127.0.0.1",
        CLANKERAUTH_PORT: String(port),
        CLANKERAUTH_MCP_ALLOWED_ORIGINS: "",
        OTEL_EXPORTER_OTLP_ENDPOINT: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  let output = "";
  child.stdout.on("data", (chunk: Buffer) => (output += chunk.toString()));
  child.stderr.on("data", (chunk: Buffer) => (output += chunk.toString()));

  const closed = once(child, "close");

  cleanups.push(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await closed;
    rmSync(directory, { recursive: true, force: true });
  });

  const waitForExit = async () => {
    await vi.waitFor(
      () => expect(child.exitCode !== null || child.signalCode !== null, output).toBe(true),
      { timeout: 10000 },
    );
    await closed;
  };

  return { child, database, url, output: () => output, waitForExit };
}

test.each(["SIGINT", "SIGTERM"] as const)(
  "%s interrupts an unfinished HTTP request and closes the database",
  async (signal) => {
    const reservation = await reservePort();
    await reservation.close();
    const server = start(reservation.port);

    await vi.waitFor(() => expect(server.output()).toContain("clankerauth ready"), {
      timeout: 10000,
    });
    const health = await fetch(`${server.url}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: "ok" });
    expect(existsSync(`${server.database}-wal`)).toBe(true);

    // The continue handshake proves the request was admitted before shutdown.
    const pending = request(`${server.url}/healthz`, {
      method: "GET",
      headers: { Expect: "100-continue", "Content-Length": "1", Connection: "close" },
    });

    cleanups.push(async () => {
      pending.destroy();
    });
    const continued = once(pending, "continue");

    const disconnected = new Promise<void>((resolve) => {
      pending.on("error", () => resolve());
      pending.on("close", () => resolve());
    });

    pending.flushHeaders();
    await continued;
    server.child.kill(signal);

    await server.waitForExit();
    await disconnected;
    // NodeRuntime uses Effect's interruption exit code for either signal.
    expect(server.child.exitCode).toBe(130);
    // SQLite removes the WAL on connection close, not on abrupt process termination.
    expect(existsSync(`${server.database}-wal`)).toBe(false);
  },
);

test("an occupied port fails startup and releases the initialized database", async () => {
  const reservation = await reservePort();
  const server = start(reservation.port);
  await server.waitForExit();
  expect(server.child.exitCode).not.toBe(0);
  expect(server.output()).toContain("EADDRINUSE");
  expect(server.output()).not.toContain("clankerauth ready");
  expect(existsSync(server.database)).toBe(true);
  expect(existsSync(`${server.database}-wal`)).toBe(false);
});
