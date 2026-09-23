// Run against a pnpm deploy --prod output, never a live database or .env.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
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

const isString = (value) => Object.prototype.toString.call(value) === "[object String]";

const env = {
  ...process.env,
  CLANKERAUTH_BASE_URL: baseURL,
  CLANKERAUTH_BETTER_AUTH_SECRET: randomBytes(32).toString("hex"),
  CLANKERAUTH_DATABASE: join(directory, "clankerauth.sqlite"),
  CLANKERAUTH_HOST: "127.0.0.1",
  CLANKERAUTH_PORT: String(port),
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

const post = (path, body, headers = {}) =>
  fetch(baseURL + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

const login = (value) =>
  post(
    "/api/auth/sign-in/email",
    { email: "package@example.internal", password: value },
    { origin: baseURL },
  );

try {
  await start();
  assert.deepEqual(await (await post("/api/issuer/setupStatus", {})).json(), { required: true });
  await stop();
  await start();
  assert.deepEqual(await (await post("/api/issuer/setupStatus", {})).json(), { required: true });

  const setup = await post(
    "/api/issuer/setupOwner",
    { email: "package@example.internal", password },
    { origin: baseURL },
  );

  assert.equal(setup.status, 201);
  assert.deepEqual(await setup.json(), { created: true });
  assert.equal(setup.headers.has("set-cookie"), true);
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

  const empty = await (
    await post("/api/administration/listClients", {}, { cookie, origin: baseURL })
  ).json();

  const builtin = {
    identifier: `${baseURL}/mcp`,
    name: "clankerauth administration",
    scopes: ["clankerauth:admin"],
    builtIn: true,
  };

  assert.deepEqual(empty.resources, [builtin]);

  const createdResource = await post("/api/administration/createResource", resource, {
    cookie,
    origin: baseURL,
  });

  assert.equal(createdResource.status, 201, await createdResource.clone().text());

  const metadata = await (
    await fetch(`${baseURL}/.well-known/oauth-authorization-server/api/auth`)
  ).json();

  assert.equal(metadata.issuer, `${baseURL}/api/auth`);
  assert.equal(metadata.client_id_metadata_document_supported, true);
  assert.equal(metadata.registration_endpoint, `${baseURL}/api/auth/oauth2/register`);

  const registration = await fetch(metadata.registration_endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "Package MCP client",
      redirect_uris: ["http://127.0.0.1:49152/callback"],
      token_endpoint_auth_method: "none",
    }),
  });

  assert.equal(registration.status, 201, await registration.clone().text());
  const registered = await registration.json();
  assert.ok(isString(registered.client_id));
  assert.equal(registered.client_secret, undefined);
  const denied = await fetch(`${baseURL}/mcp`, { method: "POST" });
  assert.equal(denied.status, 401);
  assert.match(denied.headers.get("www-authenticate"), /resource_metadata=/);

  const protectedResource = await (
    await fetch(`${baseURL}/.well-known/oauth-protected-resource/mcp`)
  ).json();

  assert.equal(protectedResource.resource, builtin.identifier);
  assert.deepEqual(protectedResource.scopes_supported, ["clankerauth:admin", "offline_access"]);
  const verifier = randomBytes(32).toString("base64url");

  const query = new URLSearchParams({
    client_id: registered.client_id,
    redirect_uri: "http://127.0.0.1:49152/callback",
    response_type: "code",
    scope: "clankerauth:admin offline_access",
    resource: builtin.identifier,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state: "package-smoke",
  });

  const authorize = await fetch(`${metadata.authorization_endpoint}?${query}`, {
    headers: { cookie, accept: "application/json" },
    redirect: "manual",
  });

  // Fetch requests receive the provider’s redirect descriptor; browser navigation uses 302.
  assert.equal(authorize.status, 200, await authorize.clone().text());
  const consentUrl = new URL((await authorize.json()).url, baseURL);
  assert.equal(consentUrl.pathname, "/consent");

  const consent = await post(
    "/api/auth/oauth2/consent",
    {
      accept: true,
      oauth_query: consentUrl.search.slice(1),
    },
    { cookie, origin: baseURL },
  );

  assert.equal(consent.status, 200, await consent.clone().text());
  const callback = new URL((await consent.json()).url);
  assert.equal(callback.searchParams.get("state"), "package-smoke");

  const tokenResponse = await fetch(metadata.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: registered.client_id,
      redirect_uri: "http://127.0.0.1:49152/callback",
      code: callback.searchParams.get("code"),
      code_verifier: verifier,
      resource: builtin.identifier,
    }),
  });

  assert.equal(tokenResponse.status, 200, await tokenResponse.clone().text());
  const token = await tokenResponse.json();
  assert.ok(isString(token.refresh_token));

  // Exercise the generated MCP adapter through the real buffered Node bridge.
  const mcp = await fetch(`${baseURL}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.access_token}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": "tools/call",
      "mcp-name": "listClients",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "listClients",
        arguments: {},
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
          "io.modelcontextprotocol/clientInfo": { name: "production-smoke", version: "0" },
        },
      },
    }),
  });

  assert.equal(mcp.status, 200);
  assert.match(mcp.headers.get("content-type"), /application\/json/);
  assert.deepEqual((await mcp.json()).result.structuredContent.value.resources, [
    builtin,
    { ...resource, builtIn: false },
  ]);
  const session = await fetch(`${baseURL}/api/auth/get-session`, { headers: { cookie } });
  assert.equal(session.status, 200);
  assert.equal(session.headers.has("set-auth-jwt"), false);

  const assets = new Set();

  for (const path of ["/", "/setup", "/login", "/consent"]) {
    const page = await fetch(baseURL + path);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /<title>clankerauth<\/title>/);
    const references = [...html.matchAll(/(?:src|href)="(\/assets\/[^" ]+)"/g)];
    assert.ok(references.length > 0);

    for (const [, asset] of references) assets.add(asset);
  }

  for (const asset of assets) assert.equal((await fetch(baseURL + asset)).status, 200);

  const blocked = await post(
    "/api/administration/blockClient",
    { client_id: registered.client_id, blocked: true },
    { cookie, origin: baseURL },
  );

  assert.equal(blocked.status, 200, await blocked.clone().text());
  const keys = await (await fetch(metadata.jwks_uri)).json();
  assert.ok(keys.keys.length > 0);
  await stop();
  await start();
  assert.deepEqual(await (await fetch(metadata.jwks_uri)).json(), keys);

  const persistedClients = await post(
    "/api/administration/listClients",
    {},
    { cookie, origin: baseURL },
  );

  assert.equal(persistedClients.status, 200);
  const persisted = await persistedClients.json();
  assert.deepEqual(persisted.resources, [builtin, { ...resource, builtIn: false }]);
  assert.equal(persisted.clients.length, 1);
  assert.equal(persisted.clients[0].client_id, registered.client_id);
  assert.equal(persisted.clients[0].onboarding, "dcr");
  assert.equal(persisted.clients[0].blocked, true);
  assert.deepEqual(await (await post("/api/issuer/setupStatus", {})).json(), { required: false });

  const repeatedSetup = await post(
    "/api/issuer/setupOwner",
    { email: "another@example.internal", password },
    { origin: baseURL },
  );

  assert.equal(repeatedSetup.status, 409);
} finally {
  await stop();
  rmSync(directory, { recursive: true, force: true });
}
