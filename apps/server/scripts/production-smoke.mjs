// Run against a pnpm deploy --prod output, never a live database or .env.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout } from "node:timers/promises";

assert.ok(process.argv[2], "Pass the production package directory");
const root = resolve(process.argv[2]);
const directory = mkdtempSync(join(tmpdir(), "clankerauth-package-"));
const reservation = createServer();
reservation.listen(0, "127.0.0.1");
await once(reservation, "listening");
const port = reservation.address().port;
await new Promise((done) => reservation.close(done));
const baseURL = `http://127.0.0.1:${port}`;
const env = {
  ...process.env,
  AUTH_BASE_URL: baseURL,
  BETTER_AUTH_SECRET: randomBytes(32).toString("hex"),
  AUTH_DATABASE: join(directory, "auth.sqlite"),
  HOST: "127.0.0.1",
  PORT: String(port),
};
const password = randomBytes(24).toString("hex");
let child;
async function start() {
  child = spawn(process.execPath, [join(root, "dist/main.mjs")], {
    cwd: directory,
    env,
    stdio: "ignore",
  });
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error("Production server exited during startup");
    try {
      if ((await fetch(`${baseURL}/healthz`, { signal: AbortSignal.timeout(500) })).ok) return;
    } catch {
      /* Listener may not yet be bound. */
    }
    await setTimeout(50);
  }
  throw new Error("Production server did not become ready");
}
async function stop() {
  if (child && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit");
    child.kill("SIGTERM");
    await exited;
  }
  child = undefined;
}
const login = (value) =>
  fetch(`${baseURL}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { origin: baseURL, "content-type": "application/json" },
    body: JSON.stringify({ email: "package@example.internal", password: value }),
  });

try {
  await start();
  assert.deepEqual(await (await fetch(`${baseURL}/api/setup`)).json(), { required: true });
  await stop();
  await start();
  assert.deepEqual(await (await fetch(`${baseURL}/api/setup`)).json(), { required: true });
  const setup = await fetch(`${baseURL}/api/setup`, {
    method: "POST",
    headers: { origin: baseURL, "content-type": "application/json" },
    body: JSON.stringify({ email: "package@example.internal", password }),
  });
  assert.equal(setup.status, 201);
  assert.deepEqual(await setup.json(), { created: true });
  assert.equal(setup.headers.has("set-cookie"), false);
  const signedIn = await login(password);
  assert.equal(signedIn.status, 200);
  const cookie = signedIn.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
  const resource = {
    identifier: "https://package.invalid/mcp",
    name: "Package MCP",
    scopes: ["read"],
  };
  const empty = await (await fetch(`${baseURL}/admin/clients`, { headers: { cookie } })).json();
  assert.deepEqual(empty.resources, []);
  const createdResource = await fetch(`${baseURL}/admin/resources`, {
    method: "POST",
    headers: { cookie, origin: baseURL, "content-type": "application/json" },
    body: JSON.stringify(resource),
  });
  assert.equal(createdResource.status, 201, await createdResource.clone().text());
  const session = await fetch(`${baseURL}/api/auth/get-session`, { headers: { cookie } });
  assert.equal(session.status, 200);
  assert.equal(session.headers.has("set-auth-jwt"), false);
  for (const path of ["/", "/setup", "/login", "/consent"]) {
    const page = await fetch(baseURL + path);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /<title>Clanker Auth<\/title>/);
    const assets = [...html.matchAll(/(?:src|href)="(\/assets\/[^" ]+)"/g)];
    assert.equal(assets.length, 2);
    for (const [, asset] of assets) assert.equal((await fetch(baseURL + asset)).status, 200);
  }
  const metadata = await (
    await fetch(`${baseURL}/.well-known/oauth-authorization-server/api/auth`)
  ).json();
  assert.equal(metadata.issuer, `${baseURL}/api/auth`);
  const keys = await (await fetch(metadata.jwks_uri)).json();
  assert.ok(keys.keys.length > 0);
  await stop();
  await start();
  assert.deepEqual(await (await fetch(metadata.jwks_uri)).json(), keys);
  const persistedClients = await fetch(`${baseURL}/admin/clients`, { headers: { cookie } });
  assert.equal(persistedClients.status, 200);
  assert.deepEqual((await persistedClients.json()).resources, [resource]);
  assert.deepEqual(await (await fetch(`${baseURL}/api/setup`)).json(), { required: false });
  const repeatedSetup = await fetch(`${baseURL}/api/setup`, {
    method: "POST",
    headers: { origin: baseURL, "content-type": "application/json" },
    body: JSON.stringify({ email: "another@example.internal", password }),
  });
  assert.equal(repeatedSetup.status, 409);
  console.log(
    "PASS production package: automatic migration, web setup/login, no session JWT header, UI/assets, discovery, persisted keys/session, setup stays closed; isolated DB and unrelated cwd",
  );
} finally {
  await stop();
  rmSync(directory, { recursive: true, force: true });
}
