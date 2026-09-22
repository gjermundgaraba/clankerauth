import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { createServer as createViteServer } from "vite";

// Run the built application against a disposable database and a real foreign-origin browser.
const directory = await mkdtemp(join(tmpdir(), "clankerauth-browser-oauth-"));

const fixture = await createViteServer({
  configFile: false,
  root: fileURLToPath(new URL("./", import.meta.url)),
  server: { host: "127.0.0.1", port: 0 },
  plugins: [
    {
      name: "oauth-browser-fixture",
      configureServer(server) {
        server.middlewares.use((request, response, next) => {
          if (!["/", "/callback"].includes(new URL(request.url, "http://fixture").pathname)) {
            return next();
          }

          response.setHeader("content-type", "text/html");
          response.end(
            '<!doctype html><title>MCP browser test</title><script type="module" src="/browser-oauth-client.js"></script>',
          );
        });
      },
    },
  ],
});

await fixture.listen();

const clientOrigin = `http://127.0.0.1:${fixture.httpServer.address().port}`;

const reservation = createServer();

reservation.listen(0, "127.0.0.1");

await once(reservation, "listening");

const port = reservation.address().port;

await new Promise((done) => reservation.close(done));

const issuer = `http://127.0.0.1:${port}`;

const password = randomBytes(24).toString("hex");

const child = spawn(
  process.execPath,
  [fileURLToPath(new URL("../dist/main.mjs", import.meta.url))],
  {
    cwd: directory,
    env: {
      ...process.env,
      AUTH_BASE_URL: issuer,
      BETTER_AUTH_SECRET: randomBytes(32).toString("hex"),
      AUTH_DATABASE: join(directory, "auth.sqlite"),
      HOST: "127.0.0.1",
      PORT: String(port),
      MCP_ALLOWED_ORIGINS: clientOrigin,
    },
    stdio: ["ignore", "pipe", "pipe"],
  },
);

let output = "";

child.stdout.on("data", (chunk) => {
  output += chunk;
});

child.stderr.on("data", (chunk) => {
  output += chunk;
});

let browser;

try {
  let ready = false;

  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(`Server exited during startup: ${output}`);

    try {
      ready = (await fetch(`${issuer}/healthz`, { signal: AbortSignal.timeout(500) })).ok;

      if (ready) break;
    } catch {
      // Startup readiness polling; the listener may not yet be bound.
    }

    await setTimeout(50);
  }

  assert.ok(ready, `Server did not become ready: ${output}`);

  const setup = await fetch(`${issuer}/api/issuer/setupOwner`, {
    method: "POST",
    headers: { origin: issuer, "content-type": "application/json" },
    body: JSON.stringify({ email: "browser@example.internal", password }),
  });

  assert.equal(setup.status, 201, await setup.text());

  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ serviceWorkers: "block" });
  page.setDefaultTimeout(15_000);
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  const tokenGrants = [];
  page.on("request", (request) => {
    if (request.url() === `${issuer}/api/auth/oauth2/token`) {
      tokenGrants.push(new URLSearchParams(request.postData()).get("grant_type"));
    }
  });
  await page.goto(`${clientOrigin}/?issuer=${encodeURIComponent(issuer)}`);
  await page.waitForFunction(() => Boolean(window.mcpTest));
  const discovery = await page.evaluate(() => window.mcpTest.inspectDiscovery());
  assert.equal(discovery.status, 401);
  assert.match(discovery.challenge, /scope="admin"/);
  assert.match(discovery.challenge, /resource_metadata=/);
  assert.deepEqual(discovery.resource.scopes_supported, ["admin", "offline_access"]);

  const start = await page.evaluate(() => window.mcpTest.connect());
  const authorization = new URL(start.authorizationUrl);
  assert.equal(authorization.origin, issuer);
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.deepEqual(
    new Set(authorization.searchParams.get("scope").split(" ")),
    new Set(["admin", "offline_access"]),
  );
  await page.goto(authorization.href);
  await page.getByLabel("Email", { exact: true }).fill("browser@example.internal");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /Sign in/ }).click();
  await page.getByRole("heading", { name: "Allow this connection?" }).waitFor();
  await page.getByRole("button", { name: /Allow access/ }).click();
  await page.waitForURL(`${clientOrigin}/callback?**`);
  await page.waitForFunction(() => Boolean(window.mcpTest));
  assert.deepEqual(await page.evaluate(() => window.mcpTest.finishAuth()), {
    hasRefreshToken: true,
  });
  assert.equal((await page.evaluate(() => window.mcpTest.connect())).connected, true);
  assert.ok((await page.evaluate(() => window.mcpTest.tools())).includes("createClient"));
  const created = await page.evaluate(() => window.mcpTest.createClient());
  assert.equal(created.isError, false, JSON.stringify(created));
  assert.equal(created.structuredContent.value.client_name, "Created by browser MCP");
  const refreshed = await page.evaluate(() => window.mcpTest.refresh());
  assert.deepEqual(refreshed, { result: "AUTHORIZED", rotated: true, hasAccessToken: true });
  assert.deepEqual(tokenGrants, ["authorization_code", "refresh_token"]);
  assert.ok((await page.evaluate(() => window.mcpTest.tools())).includes("listClients"));
  await page.evaluate(() => window.mcpTest.close());
  assert.deepEqual(pageErrors, []);
  console.log(
    "Cross-origin browser MCP OAuth passed (PKCE, consent, SDK scopes, mutation, refresh, 2026-07-28 transport).",
  );
} finally {
  await browser?.close();

  if (child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit");
    child.kill("SIGTERM");
    await exited;
  }

  await fixture.close();
  await rm(directory, { recursive: true, force: true });
}
