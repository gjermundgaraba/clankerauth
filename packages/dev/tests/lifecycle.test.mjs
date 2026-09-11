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
