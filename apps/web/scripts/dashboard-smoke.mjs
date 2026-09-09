import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { preview } from "vite";

// Exercise the shipped bundle without an API server, database, or real credentials.
await readFile(new URL("../dist/index.html", import.meta.url)); // Fail clearly if the build is missing.
const server = await preview({
  configFile: false,
  root: fileURLToPath(new URL("../", import.meta.url)),
  preview: { host: "127.0.0.1", port: 0, open: false },
});
const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
let browser;

try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ serviceWorkers: "block" });
  page.setDefaultTimeout(10_000);
  page.on("dialog", (dialog) => dialog.accept());
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const calls = [];
  const resource = {
    name: "Fixture API",
    identifier: "https://fixture.invalid/api",
    scopes: ["fixture:read"],
  };
  const existing = {
    client_id: "existing-client",
    client_name: "Existing client",
    redirect_uris: ["https://fixture.invalid/callback"],
    token_endpoint_auth_method: "client_secret_basic",
  };
  const created = { ...existing, client_id: "created-client", client_name: "Created client" };
  let data = {
    email: "owner@fixture.invalid",
    issuer: origin,
    clients: [],
    resources: [],
    clientAccess: [],
  };
  const ok = (body, status = 200) => ({ status, json: body });
  const failed = {
    status: 503,
    json: { _tag: "ServiceUnavailable", error: "Fixture request failed" },
  };
  let listResponse = async () => ok(data);
  let resourceResponse = () => ok(resource, 201);
  await page.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const key = `${request.method()} ${url.pathname}`;
    if (
      url.origin === origin &&
      (url.pathname === "/" || url.pathname === "/consent" || url.pathname.startsWith("/assets/"))
    ) {
      await route.continue();
      return;
    }
    calls.push(key);
    let response;
    if (url.origin === origin) {
      switch (key) {
        case "GET /api/setup":
          response = ok({ required: false });
          break;
        case "GET /api/auth/get-session":
          response = ok({
            session: {
              id: "fixture-session",
              userId: "fixture-owner",
              expiresAt: "2099-01-01T00:00:00.000Z",
            },
            user: {
              id: "fixture-owner",
              email: data.email,
              name: "Fixture owner",
              emailVerified: true,
            },
          });
          break;
        case "GET /admin/clients":
          response = await listResponse();
          break;
        case "POST /admin/resources":
          response = resourceResponse();
          break;
        case "POST /admin/clients":
          response = ok({ ...created, client_secret: "fixture-first-secret" }, 201);
          break;
        case "POST /admin/clients/rotate":
          response = ok({ ...created, client_secret: "fixture-rotated-secret" });
          break;
        case "GET /api/auth/oauth2/public-client":
          response = ok({
            client_id: "https://client.fixture.invalid/metadata.json",
            client_name: "<em>Client name</em>",
          });
          break;
        case "POST /admin/clients/revoke":
          assert.equal(request.postDataJSON().client_id, data.clients[0].client_id);
          response = ok({ revoked: true });
          break;
        case "POST /admin/clients/block": {
          const payload = request.postDataJSON();
          assert.equal(payload.client_id, data.clients[0].client_id);
          data = {
            ...data,
            clients: data.clients.map((client) => ({ ...client, blocked: payload.blocked })),
          };
          response = ok({ blocked: payload.blocked });
          break;
        }
        case "POST /admin/clients/delete":
          response = ok({ deleted: true });
          break;
      }
    }
    if (!response) {
      errors.push(`Unexpected network request: ${key} (${url.origin})`);
      await route.abort();
      return;
    }
    await route.fulfill(response);
  });
  const count = (key) => calls.filter((call) => call === key).length;
  const retry = page.getByRole("button", { name: "Retry refresh", exact: true });
  const savedMessage = "Saved, but the dashboard could not refresh.";
  const waitForIdle = () =>
    page.waitForFunction(() => {
      const button = document.querySelector("#resource-create button");
      return button && !button.disabled;
    });
  const waitForSaved = async () => {
    await page.locator("#message").filter({ hasText: savedMessage }).waitFor();
    await retry.waitFor();
    await waitForIdle();
    const mutations = page.locator("#dashboard-mutations");
    assert.equal(await mutations.evaluate((fieldset) => fieldset.disabled), true);
    assert.ok((await mutations.locator("input, button").count()) > 0);
    assert.equal(await mutations.locator("input:enabled, button:enabled").count(), 0);
    assert.equal(await retry.isEnabled(), true);
    const acknowledge = page.locator("#credentials button");
    if (await acknowledge.count()) assert.equal(await acknowledge.isEnabled(), true);
  };
  const resourceForm = page.locator("#resource-create");
  const fillResource = async (name) => {
    await resourceForm.locator('[name="name"]').fill(name);
    await resourceForm.locator('[name="identifier"]').fill(resource.identifier);
    await resourceForm.locator('[name="scopes"]').fill("fixture:read");
  };

  await page.goto(origin);
  await resourceForm.waitFor();
  assert.equal(await page.locator("#register button").isEnabled(), false);

  // A completed write clears the form before the list settles. Even synthetic
  // duplicate submissions must be ignored throughout the pending refresh.
  const releaseList = Promise.withResolvers();
  listResponse = async () => {
    await releaseList.promise;
    return failed;
  };
  await fillResource(resource.name);
  const listStarted = page.waitForRequest(
    (request) => request.method() === "GET" && new URL(request.url()).pathname === "/admin/clients",
  );
  await resourceForm.getByRole("button").click();
  await listStarted;
  assert.equal(await resourceForm.locator('[name="name"]').inputValue(), "");
  assert.equal(await resourceForm.getByRole("button").isEnabled(), false);
  await resourceForm.dispatchEvent("submit");
  releaseList.resolve();
  await waitForSaved();
  assert.equal(count("POST /admin/resources"), 1);
  for (const name of ["name", "identifier", "scopes"]) {
    assert.equal(await resourceForm.locator(`[name="${name}"]`).inputValue(), "");
  }

  listResponse = async () => failed;
  const beforeRetry = calls.length;
  await retry.click();
  await waitForSaved();
  assert.deepEqual(calls.slice(beforeRetry), ["GET /admin/clients"]);

  data = {
    ...data,
    resources: [resource],
    clients: [existing],
    clientAccess: [{ client_id: existing.client_id, resource: resource.identifier }],
  };
  listResponse = async () => ok(data);
  await retry.click();
  await page.getByRole("heading", { name: "Existing client", exact: true }).waitFor();
  await waitForIdle();
  assert.equal(await retry.count(), 0);
  assert.equal(await page.locator("#message").textContent(), "");
  assert.equal(await page.locator("[data-resource-delete]").isEnabled(), false);
  assert.equal(
    await page.locator("#dashboard-mutations").evaluate((fieldset) => fieldset.disabled),
    false,
  );
  assert.equal(await resourceForm.getByRole("button").isEnabled(), true);
  assert.equal(await resourceForm.locator('[name="name"]').isEnabled(), true);
  assert.equal(await page.locator("#register button").isEnabled(), true);
  assert.equal(count("POST /admin/resources"), 1);

  // A rejected write preserves user input and never offers a saved-write retry.
  resourceResponse = () => failed;
  const listsBeforeFailure = count("GET /admin/clients");
  await fillResource("Keep my draft");
  await resourceForm.getByRole("button").click();
  await page.locator("#message").filter({ hasText: "Fixture request failed" }).waitFor();
  await waitForIdle();
  assert.equal(await resourceForm.locator('[name="name"]').inputValue(), "Keep my draft");
  assert.equal(await resourceForm.locator('[name="identifier"]').inputValue(), resource.identifier);
  assert.equal(await resourceForm.locator('[name="scopes"]').inputValue(), "fixture:read");
  assert.equal(await retry.count(), 0);
  assert.equal(count("GET /admin/clients"), listsBeforeFailure);
  assert.equal((await page.locator("#message").textContent()).includes("Saved"), false);

  // One-time credentials are visible while the follow-up list is still pending.
  const releaseClientList = Promise.withResolvers();
  listResponse = async () => {
    await releaseClientList.promise;
    return failed;
  };
  const register = page.locator("#register");
  await register.locator('[name="name"]').fill(created.client_name);
  await register.locator('[name="redirect"]').fill(created.redirect_uris[0]);
  await register.locator('[name="resources"]').check();
  await register.locator('[name="confidential"]').check();
  const clientListStarted = page.waitForRequest(
    (request) => request.method() === "GET" && new URL(request.url()).pathname === "/admin/clients",
  );
  await register.getByRole("button").click();
  await clientListStarted;
  await page.locator("#credentials").filter({ hasText: "fixture-first-secret" }).waitFor();
  assert.equal(await register.locator('[name="name"]').inputValue(), "");
  assert.equal(await register.locator('[name="redirect"]').inputValue(), "");
  assert.equal(await register.locator('[name="resources"]').isChecked(), false);
  assert.equal(await register.locator('[name="confidential"]').isChecked(), false);
  await register.dispatchEvent("submit");
  releaseClientList.resolve();
  await waitForSaved();
  assert.equal(count("POST /admin/clients"), 1);
  assert.match(await page.locator("#credentials").textContent(), /fixture-first-secret/);

  data = { ...data, clients: [existing, created] };
  listResponse = async () => ok(data);
  await retry.click();
  await page.getByRole("heading", { name: created.client_name, exact: true }).waitFor();
  await waitForIdle();
  assert.match(await page.locator("#credentials").textContent(), /fixture-first-secret/);
  assert.equal(
    await page.locator("#dashboard-mutations").evaluate((fieldset) => fieldset.disabled),
    false,
  );
  assert.equal(await register.getByRole("button").isEnabled(), true);
  assert.equal(await page.locator("[data-resource-delete]").isEnabled(), false);
  assert.equal(count("POST /admin/clients"), 1);

  const listsBeforeRotation = count("GET /admin/clients");
  await page.locator('[data-rotate="created-client"]').click();
  await page.locator("#credentials").filter({ hasText: "fixture-rotated-secret" }).waitFor();
  await waitForIdle();
  assert.doesNotMatch(await page.locator("#credentials").textContent(), /fixture-first-secret/);
  assert.equal(count("GET /admin/clients"), listsBeforeRotation);
  assert.equal(count("POST /admin/clients/rotate"), 1);

  listResponse = async () => failed;
  await page.locator('[data-delete="created-client"]').click();
  await waitForSaved();
  assert.equal(await page.locator("#credentials").isVisible(), false);
  assert.equal(await page.locator("#credentials").textContent(), "");
  assert.equal(count("POST /admin/clients/delete"), 1);
  // Automatic clients expose authorization lifecycle controls without managed-only mutations.
  const automatic = {
    ...existing,
    client_id: "https://client.fixture.invalid/metadata.json",
    onboarding: "cimd",
    blocked: false,
  };
  data = {
    ...data,
    clients: [automatic],
    clientAccess: [{ client_id: automatic.client_id, resource: resource.identifier }],
  };
  listResponse = async () => ok(data);
  await retry.click();
  await page.locator(`[data-revoke="${automatic.client_id}"]`).waitFor();
  await waitForIdle();
  assert.match(await page.locator(".client").textContent(), /Client ID Metadata Document/);
  assert.equal(await page.locator("[data-client-access], [data-delete], [data-rotate]").count(), 0);
  assert.equal(await page.locator("[data-resource-delete]").isEnabled(), true);
  await page.getByRole("button", { name: "Revoke authorization", exact: true }).click();
  await waitForIdle();
  assert.equal(count("POST /admin/clients/revoke"), 1);
  await page.getByRole("button", { name: "Block client", exact: true }).click();
  await page.getByRole("button", { name: "Unblock client", exact: true }).waitFor();
  await waitForIdle();
  assert.match(await page.locator(".client").textContent(), /BLOCKED/);
  await page.getByRole("button", { name: "Unblock client", exact: true }).click();
  await page.getByRole("button", { name: "Block client", exact: true }).waitFor();
  await waitForIdle();
  assert.equal(count("POST /admin/clients/block"), 2);
  data = { ...data, clients: [{ ...automatic, onboarding: "dcr" }] };
  await page.reload();
  await page.locator(`[data-revoke="${automatic.client_id}"]`).waitFor();
  assert.match(await page.locator(".client").textContent(), /Dynamic registration/);
  assert.equal(await page.locator("[data-client-access], [data-delete], [data-rotate]").count(), 0);

  // Consent renders the actual identifier/callback and escapes client-supplied display names.
  const callback = "http://127.0.0.1:43129/callback";
  await page.goto(
    `${origin}/consent?${new URLSearchParams({ client_id: automatic.client_id, redirect_uri: callback, resource: resource.identifier, scope: "fixture:read", sig: "fixture" })}`,
  );
  await page.getByRole("heading", { name: "Allow this connection?" }).waitFor();
  const consent = await page.locator(".consent").textContent();
  assert.ok(consent.includes(automatic.client_id));
  assert.ok(consent.includes("Client metadata host: client.fixture.invalid"));
  assert.ok(consent.includes(callback));
  assert.ok(consent.includes("<em>Client name</em>"));
  assert.equal(await page.locator(".consent em").count(), 0);
  assert.deepEqual(errors, []);
  console.log("Dashboard browser regressions passed.");
} finally {
  try {
    await browser?.close();
  } finally {
    await new Promise((resolve, reject) =>
      server.httpServer.close((error) => (error ? reject(error) : resolve())),
    );
  }
}
