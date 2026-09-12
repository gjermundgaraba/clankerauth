import assert from "node:assert/strict";
import { access, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { startDisposableIssuer } from "../dist/index.mjs";

const resource = {
  identifier: "http://127.0.0.1:9876/api",
  name: "Example development API",
  scopes: ["example:read", "example:write"],
};
const options = {
  resources: [resource],
  client: {
    name: "Example console",
    redirect: "http://localhost:5173/auth/callback",
    resources: [resource.identifier],
  },
};
const login = (issuer, owner = issuer.owner) =>
  fetch(`${issuer.url}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { origin: issuer.url, "content-type": "application/json" },
    body: JSON.stringify(owner),
  });

await test("real HTTP issuer provisions resources and a confidential native client, and closes idempotently", async () => {
  const issuer = await startDisposableIssuer(options);
  try {
    assert.equal(new URL(issuer.url).hostname, "127.0.0.1");
    const discovery = await (
      await fetch(`${issuer.issuer}/.well-known/openid-configuration`)
    ).json();
    assert.equal(discovery.issuer, issuer.issuer);
    const page = await fetch(issuer.url);
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-type"), /text\/html/);
    assert.equal((await (await fetch(`${issuer.url}/api/setup`)).json()).required, false);
    assert.equal((await fetch(`${issuer.url}/admin/clients`)).status, 401);
    const session = await login(issuer);
    assert.equal(session.status, 200);
    const cookie = session.headers
      .getSetCookie()
      .map((part) => part.split(";")[0])
      .join("; ");
    await session.body.cancel();
    const state = await (
      await fetch(`${issuer.url}/admin/clients`, { headers: { cookie } })
    ).json();
    assert.equal(state.email, issuer.owner.email);
    assert.equal(state.resources.length, 1);
    assert.equal(state.resources[0].identifier, resource.identifier);
    assert.deepEqual(state.resources[0].scopes, resource.scopes);
    assert.equal(state.clients.length, 1);
    assert.equal(state.clients[0].client_id, issuer.clientId);
    assert.equal(state.clients[0].token_endpoint_auth_method, "client_secret_basic");
    assert.deepEqual(state.clients[0].redirect_uris, [options.client.redirect]);
    assert.ok(issuer.clientSecret);
    assert.equal(
      (
        await fetch(`${issuer.url}/api/setup`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: issuer.url },
          body: "x".repeat(65537),
        })
      ).status,
      413,
    );
  } finally {
    await Promise.all([issuer.close(), issuer.close()]);
  }
  await assert.rejects(access(issuer.directory), { code: "ENOENT" });
  await assert.rejects(fetch(`${issuer.url}/healthz`));
});

await test("new runs have independent credentials and identity databases", async () => {
  const first = await startDisposableIssuer(options);
  await first.close();
  const second = await startDisposableIssuer(options);
  try {
    assert.notEqual(second.directory, first.directory);
    assert.notEqual(second.clientId, first.clientId);
    assert.notEqual(second.clientSecret, first.clientSecret);
    assert.notEqual(second.owner.password, first.owner.password);
    const stale = await login(second, first.owner);
    assert.equal(stale.status, 401);
    await stale.body.cancel();
    const fresh = await login(second);
    assert.equal(fresh.status, 200);
    await fresh.body.cancel();
  } finally {
    await second.close();
  }
  await assert.rejects(access(second.directory), { code: "ENOENT" });
});

await test("failed provisioning removes its temporary directory and listening server", async () => {
  const directories = async () =>
    (await readdir(tmpdir())).filter((name) => name.startsWith("clankerauth-disposable-")).sort();
  const before = await directories();
  await assert.rejects(
    startDisposableIssuer({ ...options, resources: [{ ...resource, identifier: "invalid" }] }),
    /provisioning failed/,
  );
  assert.deepEqual(await directories(), before);
});

await test("bundled provider preserves complete key listings and fixed verification windows", async (context) => {
  const issuer = await startDisposableIssuer(options);
  try {
    const session = await login(issuer);
    assert.equal(session.status, 200);
    const cookie = session.headers
      .getSetCookie()
      .map((part) => part.split(";")[0])
      .join("; ");
    await session.body.cancel();
    const headers = { cookie, origin: issuer.url, "content-type": "application/json" };
    let first;
    for (let index = 0; index < 101; index++) {
      const response = await fetch(`${issuer.url}/admin/api-keys`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: `Development key ${index}`,
          permissions: { [resource.identifier]: ["example:read"] },
          expiresAt: null,
        }),
      });
      assert.equal(response.status, 201);
      const key = await response.json();
      first ??= key;
    }
    const listing = await (await fetch(`${issuer.url}/admin/api-keys`, { headers })).json();
    assert.equal(listing.keys.length, 101);
    assert.ok(listing.keys.some((key) => key.name === "Development key 100"));
    assert.ok(!JSON.stringify(listing).includes(first.key));
    context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
    for (let index = 0; index < 1100; index++) {
      const response = await fetch(`${issuer.url}/api/api-keys/verify`, {
        method: "POST",
        headers: { authorization: `Bearer ${first.key}`, "content-type": "application/json" },
        body: JSON.stringify({ resource: resource.identifier }),
      });
      assert.equal(
        response.status,
        200,
        `steady verification ${index + 1} must remain below the per-minute limit`,
      );
      await response.body.cancel();
      context.mock.timers.tick(1000);
    }
  } finally {
    context.mock.timers.reset();
    await issuer.close();
  }
});

await test("test hooks serve CIMD fixtures and observe real issuer HTTP requests", async () => {
  const requests = [];
  const metadataRequests = [];
  const clientId = "https://fixture.example/oauth/client.json";
  const redirect = "http://127.0.0.1:8765/callback";
  const issuer = await startDisposableIssuer({
    ...options,
    onRequest(request) {
      assert.deepEqual(Object.keys(request).sort(), ["method", "url"]);
      assert.ok(request.url instanceof URL);
      requests.push({ method: request.method, url: request.url.href });
    },
    cimdTransport(input, init) {
      metadataRequests.push(new Request(input, init));
      return Response.json({
        client_id: clientId,
        client_name: "Fixture metadata client",
        redirect_uris: [redirect],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      });
    },
  });
  try {
    assert.ok(requests.some((request) => request.url === `${issuer.url}/api/setup`));
    requests.length = 0;
    const discoveryURL = `${issuer.issuer}/.well-known/openid-configuration`;
    const discoveryResponse = await fetch(discoveryURL);
    assert.equal(discoveryResponse.status, 200);
    const discovery = await discoveryResponse.json();
    const keys = await fetch(discovery.jwks_uri);
    assert.equal(keys.status, 200);
    assert.ok(Array.isArray((await keys.json()).keys));
    const registration = await fetch(discovery.registration_endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Dynamic fixture client",
        redirect_uris: [redirect],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    });
    assert.equal(registration.status, 201);
    const registered = await registration.json();
    const tokens = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: registered.client_id,
        code: "invalid-test-code",
        code_verifier: "a".repeat(43),
        redirect_uri: redirect,
      }),
    });
    assert.equal(tokens.status, 400);
    await tokens.body.cancel();
    assert.deepEqual(requests, [
      { method: "GET", url: discoveryURL },
      { method: "GET", url: discovery.jwks_uri },
      { method: "POST", url: discovery.registration_endpoint },
      { method: "POST", url: discovery.token_endpoint },
    ]);
    const authorizationURL = new URL(discovery.authorization_endpoint);
    authorizationURL.search = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirect,
      response_type: "code",
      scope: "openid example:read",
      resource: resource.identifier,
      code_challenge: "a".repeat(43),
      code_challenge_method: "S256",
      state: "fixture-state",
    }).toString();
    const authorization = await fetch(authorizationURL, { redirect: "manual" });
    assert.equal(authorization.status, 200);
    const authorizationResult = await authorization.json();
    assert.match(authorizationResult.url, /\/login/);
    assert.equal(metadataRequests.length, 1);
    assert.equal(metadataRequests[0].url, clientId);
    assert.equal(metadataRequests[0].method, "GET");
    assert.deepEqual(requests.at(-1), { method: "GET", url: authorizationURL.href });
  } finally {
    await issuer.close();
  }
});
