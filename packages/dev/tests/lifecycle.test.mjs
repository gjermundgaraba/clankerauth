import assert from "node:assert/strict";
import { access, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { request } from "node:http";
import { once } from "node:events";
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
      await fetch(`${issuer.issuer}/.well-known/oauth-authorization-server`)
    ).json();

    assert.equal(discovery.issuer, issuer.issuer);
    const page = await fetch(issuer.url);
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-type"), /text\/html/);
    assert.equal(
      (
        await (
          await fetch(`${issuer.url}/api/issuer/setupStatus`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: "{}",
          })
        ).json()
      ).required,
      false,
    );
    assert.equal(
      (
        await fetch(`${issuer.url}/api/administration/listClients`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        })
      ).status,
      401,
    );
    const session = await login(issuer);
    assert.equal(session.status, 200);

    const cookie = session.headers
      .getSetCookie()
      .map((part) => part.split(";")[0])
      .join("; ");

    await session.body.cancel();

    const state = await (
      await fetch(`${issuer.url}/api/administration/listClients`, {
        method: "POST",
        headers: { cookie, origin: issuer.url, "content-type": "application/json" },
        body: "{}",
      })
    ).json();

    assert.equal(state.email, issuer.owner.email);
    assert.equal(state.resources.length, 2);
    assert.deepEqual(
      state.resources.find((item) => item.identifier === resource.identifier),
      { ...resource, builtIn: false },
    );
    assert.ok(state.resources.some((item) => item.identifier === `${issuer.url}/mcp`));
    assert.equal(state.clients.length, 1);
    assert.equal(state.clients[0].client_id, issuer.clientId);
    assert.equal(state.clients[0].token_endpoint_auth_method, "client_secret_basic");
    assert.deepEqual(state.clients[0].redirect_uris, [options.client.redirect]);
    assert.ok(issuer.clientSecret);
    // Oversized bodies are disconnected by the body limit rather than answered.
    await assert.rejects(
      fetch(`${issuer.url}/api/issuer/setupOwner`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: issuer.url },
        body: "x".repeat(65537),
      }),
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

await test("bundled provider lists key metadata without plaintext and verifies keys online", async () => {
  const issuer = await startDisposableIssuer(options);

  try {
    const session = await login(issuer);
    assert.equal(session.status, 200);

    const cookie = session.headers
      .getSetCookie()
      .map((part) => part.split(";")[0])
      .join("; ");

    await session.body.cancel();
    const headers = { cookie, "content-type": "application/json" };
    const created = [];

    for (let index = 0; index < 3; index++) {
      const response = await fetch(`${issuer.url}/api/administration/createApiKey`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: `Development key ${index}`,
          permissions: { [resource.identifier]: ["example:read"] },
          expiresAt: null,
        }),
      });

      assert.equal(response.status, 201);
      created.push(await response.json());
    }

    const listing = await (
      await fetch(`${issuer.url}/api/administration/listApiKeys`, {
        method: "POST",
        headers,
        body: "{}",
      })
    ).json();

    assert.deepEqual(
      listing.keys.map((key) => key.name),
      created.map((key) => key.name),
    );

    for (const key of created) assert.ok(!JSON.stringify(listing).includes(key.key));

    const verify = () =>
      fetch(`${issuer.url}/api/issuer/verifyApiKey`, {
        method: "POST",
        headers: { authorization: `Bearer ${created[0].key}`, "content-type": "application/json" },
        body: JSON.stringify({ resource: resource.identifier }),
      });

    const verified = await verify();
    assert.equal(verified.status, 200);
    assert.deepEqual((await verified.json()).scopes, ["example:read"]);

    const disabled = await fetch(`${issuer.url}/api/administration/updateApiKey`, {
      method: "POST",
      headers,
      body: JSON.stringify({ keyId: created[0].keyId, enabled: false }),
    });

    assert.equal(disabled.status, 200);
    await disabled.body.cancel();
    const rejected = await verify();
    assert.equal(rejected.status, 401);
    await rejected.body.cancel();
  } finally {
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
    // Provisioning is in-process; only the test's own traffic reaches the listener.
    assert.deepEqual(requests, []);
    const discoveryURL = `${issuer.issuer}/.well-known/oauth-authorization-server`;
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
      scope: "example:read",
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

await test(
  "close interrupts an unfinished HTTP request and removes its database",
  { timeout: 10000 },
  async () => {
    const issuer = await startDisposableIssuer(options);

    const pending = request(`${issuer.url}/healthz`, {
      headers: { Expect: "100-continue", "Content-Length": "1" },
    });

    const disconnected = new Promise((resolve) => {
      pending.on("error", resolve);
      pending.on("close", resolve);
    });

    try {
      const continued = once(pending, "continue");
      pending.flushHeaders();
      await continued;
      await issuer.close();
      await disconnected;
      await assert.rejects(access(issuer.directory), { code: "ENOENT" });
    } finally {
      pending.destroy();
      await issuer.close();
    }
  },
);
