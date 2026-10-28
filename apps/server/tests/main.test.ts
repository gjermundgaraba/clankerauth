import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, request } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vite-plus/test";

const cleanups: Array<() => Promise<void>> = [];

const reservePort = async () => {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();

  if (address === null || !(address instanceof Object)) {
    throw new Error("Expected TCP address");
  }

  const close = async () => {
    if (server.listening) {
      server.close();
      await once(server, "close");
    }
  };

  cleanups.push(close);

  return { port: address.port, close };
};

const start = (port: number) => {
  const directory = mkdtempSync(path.join(tmpdir(), "clankerauth-main-"));
  const database = path.join(directory, "clankerauth.sqlite");
  const url = `http://127.0.0.1:${port}`;

  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL("../src/main.ts", import.meta.url))],
    {
      cwd: directory,
      env: {
        ...process.env,
        CLANKERAUTH_BASE_URL: url,
        CLANKERAUTH_BETTER_AUTH_SECRET:
          "test-only-secret-with-at-least-32-characters",
        CLANKERAUTH_DATABASE: database,
        CLANKERAUTH_HOST: "127.0.0.1",
        CLANKERAUTH_PORT: String(port),
        CLANKERAUTH_MCP_ALLOWED_ORIGINS: "",
        OTEL_EXPORTER_OTLP_ENDPOINT: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    }
  );

  let output = "";
  child.stdout.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });

  const closed = once(child, "close");

  cleanups.push(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }

    await closed;
    rmSync(directory, { recursive: true, force: true });
  });

  const waitForExit = async () => {
    await vi.waitFor(
      () => {
        expect(
          child.exitCode !== null || child.signalCode !== null,
          output
        ).toBe(true);
      },
      { timeout: 10_000 }
    );
    await closed;
  };

  return { child, database, url, output: () => output, waitForExit };
};

describe("server process", () => {
  afterEach(async () => {
    for (const cleanup of cleanups.splice(0).toReversed()) {
      await cleanup();
    }
  });

  it.each(["SIGINT", "SIGTERM"] as const)(
    "%s interrupts an unfinished HTTP request and closes the database",
    async (signal) => {
      const reservation = await reservePort();
      await reservation.close();
      const server = start(reservation.port);

      await vi.waitFor(
        () => {
          expect(server.output()).toContain("clankerauth ready");
        },
        {
          timeout: 10_000,
        }
      );
      const health = await fetch(`${server.url}/healthz`);
      expect(health.status).toBe(200);
      await expect(health.json()).resolves.toStrictEqual({ status: "ok" });
      expect(existsSync(`${server.database}-wal`)).toBe(true);

      const pending = request(`${server.url}/healthz`, {
        method: "GET",
        headers: {
          Expect: "100-continue",
          "Content-Length": "1",
          Connection: "close",
        },
      });

      cleanups.push(async () => {
        pending.destroy();
      });
      const continued = once(pending, "continue");

      const disconnected = Promise.race([
        once(pending, "error"),
        once(pending, "close"),
      ]);

      pending.flushHeaders();
      await continued;
      server.child.kill(signal);

      await server.waitForExit();
      await disconnected;
      expect(server.child.exitCode).toBe(130);
      expect(existsSync(`${server.database}-wal`)).toBe(false);
    }
  );

  it("an occupied port fails startup and releases the initialized database", async () => {
    const reservation = await reservePort();
    const server = start(reservation.port);
    await server.waitForExit();
    expect(server.child.exitCode).not.toBe(0);
    expect(server.output()).toContain("EADDRINUSE");
    expect(server.output()).not.toContain("clankerauth ready");
    expect(existsSync(server.database)).toBe(true);
    expect(existsSync(`${server.database}-wal`)).toBe(false);
  });
});
