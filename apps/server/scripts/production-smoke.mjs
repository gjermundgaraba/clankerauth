import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout } from "node:timers/promises";

import { ClientListResult } from "@gjermundgaraba/clankerauth-admin-api";
import { Schema } from "effect";

const packageDirectory = process.argv.at(2);

assert.ok(
  packageDirectory !== undefined && packageDirectory !== "",
  "Pass the production package directory"
);

const root = path.resolve(packageDirectory);

const directory = mkdtempSync(path.join(tmpdir(), "clankerauth-package-"));

const reservation = createServer();

reservation.listen(0, "127.0.0.1");

await once(reservation, "listening");

const { port } = reservation.address();

reservation.close();

await once(reservation, "close");

const baseURL = `http://127.0.0.1:${port}`;

const env = {
  ...process.env,
  CLANKERAUTH_BASE_URL: baseURL,
  CLANKERAUTH_BETTER_AUTH_SECRET: randomBytes(32).toString("hex"),
  CLANKERAUTH_DATABASE: path.join(directory, "clankerauth.sqlite"),
  CLANKERAUTH_HOST: "127.0.0.1",
  CLANKERAUTH_PORT: String(port),
};

const password = randomBytes(24).toString("hex");

/** @type {import("node:child_process").ChildProcess | undefined} */
let child;

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
  child = spawn(process.execPath, [path.join(root, "dist/main.mjs")], {
    cwd: directory,
    env,
    stdio: "ignore",
  });

  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) {
      throw new Error("Production server exited during startup");
    }

    if (await isHealthy()) {
      return;
    }

    await setTimeout(50);
  }

  throw new Error("Production server did not become ready");
};

const stop = async () => {
  if (child && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit");
    child.kill("SIGTERM");
    await exited;
  }

  child = undefined;
};

const decodeMetadata = Schema.decodeUnknownSync(
  Schema.Struct({
    issuer: Schema.String,
    client_id_metadata_document_supported: Schema.Boolean,
    registration_endpoint: Schema.String,
    authorization_endpoint: Schema.String,
    token_endpoint: Schema.String,
    jwks_uri: Schema.String,
  })
);

const decodeRegistration = Schema.decodeUnknownSync(
  Schema.Struct({
    client_id: Schema.String,
    client_secret: Schema.optional(Schema.String),
  })
);

const decodeProtectedResource = Schema.decodeUnknownSync(
  Schema.Struct({
    resource: Schema.String,
    scopes_supported: Schema.Array(Schema.String),
  })
);

const decodeRedirect = Schema.decodeUnknownSync(
  Schema.Struct({ url: Schema.String })
);

const decodeTokens = Schema.decodeUnknownSync(
  Schema.Struct({ access_token: Schema.String, refresh_token: Schema.String })
);

const decodeToolResult = Schema.decodeUnknownSync(
  Schema.Struct({
    result: Schema.Struct({
      structuredContent: Schema.Struct({ resources: Schema.Unknown }),
    }),
  })
);

const decodeKeys = Schema.decodeUnknownSync(
  Schema.Struct({ keys: Schema.Array(Schema.Unknown) })
);

const decodeClients = Schema.decodeUnknownSync(ClientListResult, {
  onExcessProperty: "error",
});

const post = async (pathname, body, headers = {}) =>
  await fetch(baseURL + pathname, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

/** @param {string} value */
const login = async (value) =>
  await post(
    "/api/auth/sign-in/email",
    { email: "package@example.internal", password: value },
    { origin: baseURL }
  );

try {
  await start();
  const required = await post("/api/setupStatus", {});
  assert.deepEqual(await required.json(), { required: true });
  await stop();
  await start();
  const stillRequired = await post("/api/setupStatus", {});
  assert.deepEqual(await stillRequired.json(), { required: true });

  const setup = await post(
    "/api/setupOwner",
    { email: "package@example.internal", password },
    { origin: baseURL }
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

  const listed = await post(
    "/api/listClients",
    {},
    { cookie, origin: baseURL }
  );

  const empty = decodeClients(await listed.json());

  const builtin = {
    identifier: `${baseURL}/`,
    name: "clankerauth administration",
    scopes: ["clankerauth:read", "clankerauth:write"],
    builtIn: true,
  };

  assert.deepEqual(empty.resources, [builtin]);

  const createdResource = await post("/api/putResource", resource, {
    cookie,
    origin: baseURL,
  });

  assert.equal(
    createdResource.status,
    200,
    await createdResource.clone().text()
  );

  const discovery = await fetch(
    `${baseURL}/.well-known/oauth-authorization-server/api/auth`
  );

  const metadata = decodeMetadata(await discovery.json());
  assert.equal(metadata.issuer, `${baseURL}/api/auth`);
  assert.equal(metadata.client_id_metadata_document_supported, true);
  assert.equal(
    metadata.registration_endpoint,
    `${baseURL}/api/auth/oauth2/register`
  );

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
  const registered = decodeRegistration(await registration.json());
  assert.equal(registered.client_secret, undefined);
  const denied = await fetch(`${baseURL}/mcp`, { method: "POST" });
  assert.equal(denied.status, 401);

  const resourceDiscovery = await fetch(
    `${baseURL}/.well-known/oauth-protected-resource`
  );

  const protectedResource = decodeProtectedResource(
    await resourceDiscovery.json()
  );

  assert.equal(protectedResource.resource, builtin.identifier);
  assert.deepEqual(protectedResource.scopes_supported, [
    "clankerauth:read",
    "clankerauth:write",
    "offline_access",
  ]);
  const verifier = randomBytes(32).toString("base64url");

  const query = new URLSearchParams({
    client_id: registered.client_id,
    redirect_uri: "http://127.0.0.1:49152/callback",
    response_type: "code",
    scope: "clankerauth:read clankerauth:write offline_access",
    resource: builtin.identifier,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state: "package-smoke",
  });

  const authorize = await fetch(`${metadata.authorization_endpoint}?${query}`, {
    headers: { cookie, accept: "application/json" },
    redirect: "manual",
  });

  assert.equal(authorize.status, 200, await authorize.clone().text());

  const consentUrl = new URL(
    decodeRedirect(await authorize.json()).url,
    baseURL
  );

  assert.equal(consentUrl.pathname, "/consent");

  const consent = await post(
    "/api/auth/oauth2/consent",
    {
      accept: true,
      oauth_query: consentUrl.search.slice(1),
    },
    { cookie, origin: baseURL }
  );

  assert.equal(consent.status, 200, await consent.clone().text());
  const callback = new URL(decodeRedirect(await consent.json()).url);
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
  const token = decodeTokens(await tokenResponse.json());

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
          "io.modelcontextprotocol/clientInfo": {
            name: "production-smoke",
            version: "0",
          },
        },
      },
    }),
  });

  assert.equal(mcp.status, 200);
  const reply = decodeToolResult(await mcp.json());
  assert.deepEqual(reply.result.structuredContent.resources, [
    builtin,
    { ...resource, builtIn: false },
  ]);

  const session = await fetch(`${baseURL}/api/auth/get-session`, {
    headers: { cookie },
  });

  assert.equal(session.status, 200);
  assert.equal(session.headers.has("set-auth-jwt"), false);

  const assets = new Set();

  for (const route of [
    "/",
    "/resources",
    "/keys",
    "/setup",
    "/login",
    "/consent",
  ]) {
    const page = await fetch(baseURL + route);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /<title>clankerauth<\/title>/u);

    const references = [
      ...html.matchAll(/(?:src|href)="(?<asset>\/assets\/[^" ]+)"/gu),
    ];

    assert.ok(references.length > 0);

    for (const reference of references) {
      const asset = reference.groups?.["asset"];
      assert.ok(asset !== undefined, reference[0]);
      assets.add(asset);
    }
  }

  for (const asset of assets) {
    const served = await fetch(baseURL + asset);
    assert.equal(served.status, 200);
  }

  const blocked = await post(
    "/api/blockClient",
    { client_id: registered.client_id, blocked: true },
    { cookie, origin: baseURL }
  );

  assert.equal(blocked.status, 200, await blocked.clone().text());
  const published = await fetch(metadata.jwks_uri);
  /** @type {unknown} */
  const keys = await published.json();
  assert.ok(decodeKeys(keys).keys.length > 0);
  await stop();
  await start();
  const republished = await fetch(metadata.jwks_uri);
  assert.deepEqual(await republished.json(), keys);

  const persistedClients = await post(
    "/api/listClients",
    {},
    { cookie, origin: baseURL }
  );

  assert.equal(persistedClients.status, 200);
  const persisted = decodeClients(await persistedClients.json());
  assert.deepEqual(persisted.resources, [
    builtin,
    { ...resource, builtIn: false },
  ]);
  assert.equal(persisted.clients.length, 1);
  assert.equal(persisted.clients[0].client_id, registered.client_id);
  assert.equal(persisted.clients[0].onboarding, "dcr");
  assert.equal(persisted.clients[0].blocked, true);
  const completed = await post("/api/setupStatus", {});
  assert.deepEqual(await completed.json(), { required: false });

  const repeatedSetup = await post(
    "/api/setupOwner",
    { email: "another@example.internal", password },
    { origin: baseURL }
  );

  assert.equal(repeatedSetup.status, 409);
} finally {
  await stop();
  rmSync(directory, { recursive: true, force: true });
}
