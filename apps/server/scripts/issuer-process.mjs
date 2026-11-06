import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:net";
import path from "node:path";
import { setTimeout } from "node:timers/promises";

const freePort = async () => {
  const reservation = createServer();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const address = reservation.address();
  reservation.close();
  await once(reservation, "close");

  if (!(address instanceof Object)) {
    throw new TypeError("Expected a TCP reservation");
  }

  return address.port;
};

/**
 * A built issuer, `main`, run as its own process on a free loopback port with its database
 * in `directory`. `start` waits until `/healthz` answers; `stop` ends it with SIGTERM, and a
 * later `start` serves the same database and secret again. A failure carries the process's
 * output so far.
 *
 * @param {{ readonly main: string; readonly directory: string; readonly env?: Record<string, string> }} options
 */
export const issuerProcess = async ({ main, directory, env = {} }) => {
  const port = await freePort();
  const baseURL = `http://127.0.0.1:${port}`;

  const environment = {
    ...process.env,
    CLANKERAUTH_BASE_URL: baseURL,
    CLANKERAUTH_BETTER_AUTH_SECRET: randomBytes(32).toString("hex"),
    CLANKERAUTH_DATABASE: path.join(directory, "clankerauth.sqlite"),
    CLANKERAUTH_HOST: "127.0.0.1",
    CLANKERAUTH_PORT: String(port),
    ...env,
  };

  /** @type {import("node:child_process").ChildProcess | undefined} */
  let child;
  let output = "";

  const isHealthy = async () => {
    try {
      const health = await fetch(`${baseURL}/healthz`, {
        signal: AbortSignal.timeout(500),
      });

      return health.ok;
    } catch {
      return false;
    }
  };

  const start = async () => {
    output = "";

    const started = spawn(process.execPath, [main], {
      cwd: directory,
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
    });

    child = started;

    const collect = (chunk) => {
      output += chunk;
    };

    started.stdout.on("data", collect);
    started.stderr.on("data", collect);

    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (started.exitCode !== null) {
        throw new Error(`Issuer exited during startup: ${output}`);
      }

      if (await isHealthy()) {
        return;
      }

      await setTimeout(50);
    }

    throw new Error(`Issuer did not become ready: ${output}`);
  };

  const stop = async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      await exited;
    }

    child = undefined;
  };

  return { baseURL, start, stop };
};
