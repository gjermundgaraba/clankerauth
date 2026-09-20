import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { ServiceUnavailable } from "@clankerauth/api";
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
  const registrations = [];
  const keyUpdates = [];

  const resource = {
    builtIn: false,
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
    json: new ServiceUnavailable({ error: "Fixture request failed" }),
  };

  let machineKeys = [];
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
        case "POST /api/issuer/setupStatus":
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
        case "POST /api/administration/listApiKeys":
          response = ok({ keys: machineKeys });
          break;
        case "POST /api/administration/createApiKey": {
          const payload = request.postDataJSON();
          assert.deepEqual(payload.permissions, { [resource.identifier]: ["fixture:read"] });
          assert.equal(payload.expiresAt, null);

          const key = {
            keyId: "fixture-key",
            ...payload,
            enabled: true,
            createdAt: "2026-09-10T12:00:00.000Z",
          };

          machineKeys.push(key);
          response = ok({ ...key, key: "ca_fixture-once-only" }, 201);
          break;
        }

        case "POST /api/administration/updateApiKey": {
          const payload = request.postDataJSON();
          keyUpdates.push(payload);
          machineKeys = machineKeys.map((key) =>
            key.keyId === payload.keyId ? { ...key, ...payload } : key,
          );
          response = ok(machineKeys.find((key) => key.keyId === payload.keyId));
          break;
        }

        case "POST /api/administration/deleteApiKey":
          machineKeys = [];
          response = ok({ deleted: true });
          break;
        case "POST /api/administration/listClients":
          response = await listResponse();
          break;
        case "POST /api/administration/updateResource": {
          const payload = request.postDataJSON();

          const previous = data.resources.find(
            (resource) => resource.identifier === payload.identifier,
          );

          assert.ok(previous);

          if (previous.builtIn) assert.deepEqual(payload.scopes, ["admin"]);
          data.resources = data.resources.map((resource) =>
            resource.identifier === payload.identifier ? { ...resource, ...payload } : resource,
          );
          response = ok(payload);
          break;
        }

        case "POST /api/administration/createResource":
          response = resourceResponse();
          break;
        case "POST /api/administration/createClient":
          registrations.push(request.postDataJSON());
          response = ok({ ...created, client_secret: "fixture-first-secret" }, 201);
          break;
        case "POST /api/administration/rotateClientSecret":
          response = ok({ ...created, client_secret: "fixture-rotated-secret" });
          break;
        case "GET /api/auth/oauth2/public-client":
          response = ok({
            client_id: "https://client.fixture.invalid/metadata.json",
            client_name: "<em>Client name</em>",
          });
          break;
        case "POST /api/administration/revokeClient":
          assert.equal(request.postDataJSON().client_id, data.clients[0].client_id);
          response = ok({ revoked: true });
          break;
        case "POST /api/administration/blockClient": {
          const payload = request.postDataJSON();
          assert.equal(payload.client_id, data.clients[0].client_id);
          data = {
            ...data,
            clients: data.clients.map((client) => ({ ...client, blocked: payload.blocked })),
          };
          response = ok({ blocked: payload.blocked });
          break;
        }

        case "POST /api/administration/deleteClient":
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
  // Registration works before the resource catalog exists and sends an empty selection.
  const emptyRegister = page.locator("#register");
  assert.equal(await emptyRegister.getByRole("button").isEnabled(), true);
  assert.equal(await emptyRegister.locator('[name="resources"]').count(), 0);
  await emptyRegister.locator('[name="name"]').fill(created.client_name);
  await emptyRegister.locator('[name="redirect_uris"]').fill(created.redirect_uris[0]);
  await emptyRegister
    .locator('[name="token_endpoint_auth_method"]')
    .selectOption("client_secret_basic");
  await emptyRegister.getByRole("button").click();
  await page.locator("#credentials").filter({ hasText: "fixture-first-secret" }).waitFor();
  await waitForIdle();
  assert.equal(count("POST /api/administration/createClient"), 1);
  assert.deepEqual(registrations[0].resources, []);
  await page.locator("#credentials button").click();

  // A completed write clears the form before the list settles. Even synthetic
  // duplicate submissions must be ignored throughout the pending refresh.
  const releaseList = Promise.withResolvers();
  listResponse = async () => {
    await releaseList.promise;

    return failed;
  };

  await fillResource(resource.name);

  const listStarted = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/api/administration/listClients",
  );

  await resourceForm.getByRole("button").click();
  await listStarted;
  assert.equal(await resourceForm.locator('[name="name"]').inputValue(), "");
  assert.equal(await resourceForm.getByRole("button").isEnabled(), false);
  await resourceForm.dispatchEvent("submit");
  releaseList.resolve();
  await waitForSaved();
  assert.equal(count("POST /api/administration/createResource"), 1);

  for (const name of ["name", "identifier", "scopes"]) {
    assert.equal(await resourceForm.locator(`[name="${name}"]`).inputValue(), "");
  }

  listResponse = async () => failed;
  const beforeRetry = calls.length;
  await retry.click();
  await waitForSaved();
  assert.deepEqual(calls.slice(beforeRetry), [
    "POST /api/administration/listClients",
    "POST /api/administration/listApiKeys",
  ]);

  data = {
    ...data,
    resources: [
      resource,
      {
        identifier: `${origin}/mcp`,
        name: "Clanker Auth administration",
        scopes: ["admin"],
        builtIn: true,
      },
    ],
    clients: [existing],
    clientAccess: [{ client_id: existing.client_id, resource: resource.identifier }],
  };
  listResponse = async () => ok(data);
  await retry.click();
  await page.getByRole("heading", { name: "Existing client", exact: true }).waitFor();
  await waitForIdle();
  assert.equal(await retry.count(), 0);
  assert.equal(await page.locator("#message").textContent(), "");
  const builtInEdit = page.locator(`[data-resource-edit="${origin}/mcp"]`);
  await builtInEdit.locator("..").getByText("Edit resource", { exact: true }).click();
  assert.equal(await builtInEdit.locator('[name="scopes"]').count(), 0);
  await builtInEdit.locator('[name="name"]').fill("My administration");
  await builtInEdit.getByRole("button", { name: "Save resource", exact: true }).click();
  await page.getByRole("heading", { name: "My administration", exact: true }).waitFor();
  await waitForIdle();
  assert.equal(
    await page.locator("#key-create").getByText("My administration", { exact: true }).count(),
    0,
  );
  assert.equal(await page.locator("[data-resource-delete]").count(), 1);
  assert.equal(await page.locator("[data-resource-delete]").isEnabled(), true);
  assert.equal(
    await page.locator("#dashboard-mutations").evaluate((fieldset) => fieldset.disabled),
    false,
  );
  assert.equal(await resourceForm.getByRole("button").isEnabled(), true);
  assert.equal(await resourceForm.locator('[name="name"]').isEnabled(), true);
  assert.equal(await page.locator("#register button").isEnabled(), true);
  assert.equal(count("POST /api/administration/createResource"), 1);

  // A rejected write preserves user input and never offers a saved-write retry.
  resourceResponse = () => failed;
  const listsBeforeFailure = count("POST /api/administration/listClients");
  await fillResource("Keep my draft");
  await resourceForm.getByRole("button").click();
  await page.locator("#message").filter({ hasText: "Fixture request failed" }).waitFor();
  await waitForIdle();
  assert.equal(await resourceForm.locator('[name="name"]').inputValue(), "Keep my draft");
  assert.equal(await resourceForm.locator('[name="identifier"]').inputValue(), resource.identifier);
  assert.equal(await resourceForm.locator('[name="scopes"]').inputValue(), "fixture:read");
  assert.equal(await retry.count(), 0);
  assert.equal(count("POST /api/administration/listClients"), listsBeforeFailure);
  assert.equal((await page.locator("#message").textContent()).includes("Saved"), false);

  // One-time credentials are visible while the follow-up list is still pending.
  const releaseClientList = Promise.withResolvers();
  listResponse = async () => {
    await releaseClientList.promise;

    return failed;
  };

  const register = page.locator("#register");
  await register.locator('[name="name"]').fill(created.client_name);
  await register.locator('[name="redirect_uris"]').fill(created.redirect_uris.join("\n"));
  await register.locator(`[name="resources"][value="${resource.identifier}"]`).check();
  await register.locator('[name="token_endpoint_auth_method"]').selectOption("client_secret_basic");

  const clientListStarted = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/api/administration/listClients",
  );

  await register.getByRole("button").click();
  await clientListStarted;
  await page.locator("#credentials").filter({ hasText: "fixture-first-secret" }).waitFor();
  assert.equal(await register.locator('[name="name"]').inputValue(), "");
  assert.equal(await register.locator('[name="redirect_uris"]').inputValue(), "");
  assert.equal(
    await register.locator(`[name="resources"][value="${resource.identifier}"]`).isChecked(),
    false,
  );
  assert.equal(await register.locator('[name="token_endpoint_auth_method"]').inputValue(), "none");
  await register.dispatchEvent("submit");
  releaseClientList.resolve();
  await waitForSaved();
  assert.equal(count("POST /api/administration/createClient"), 2);
  assert.deepEqual(registrations[1].resources, [resource.identifier]);
  assert.deepEqual(registrations[1].redirect_uris, created.redirect_uris);
  assert.equal(registrations[1].token_endpoint_auth_method, "client_secret_basic");
  assert.equal(registrations[1].client_name, created.client_name);
  assert.equal(registrations[1].application_type, "web");
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
  assert.equal(await page.locator("[data-resource-delete]").isEnabled(), true);
  assert.equal(count("POST /api/administration/createClient"), 2);

  const listsBeforeRotation = count("POST /api/administration/listClients");
  await page.locator('[data-rotate="created-client"]').click();
  await page.locator("#credentials").filter({ hasText: "fixture-rotated-secret" }).waitFor();
  await waitForIdle();
  assert.doesNotMatch(await page.locator("#credentials").textContent(), /fixture-first-secret/);
  assert.equal(count("POST /api/administration/listClients"), listsBeforeRotation);
  assert.equal(count("POST /api/administration/rotateClientSecret"), 1);

  listResponse = async () => failed;
  await page.locator('[data-delete="created-client"]').click();
  await waitForSaved();
  assert.equal(await page.locator("#credentials").isVisible(), false);
  assert.equal(await page.locator("#credentials").textContent(), "");
  assert.equal(count("POST /api/administration/deleteClient"), 1);

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
  assert.equal(await page.locator("[data-client-edit], [data-delete], [data-rotate]").count(), 0);
  assert.equal(await page.locator("[data-client-access]").count(), 1);
  assert.equal(await page.locator("[data-resource-delete]").isEnabled(), true);
  await page.getByRole("button", { name: "Revoke authorization", exact: true }).click();
  await waitForIdle();
  assert.equal(count("POST /api/administration/revokeClient"), 1);
  await page.getByRole("button", { name: "Block client", exact: true }).click();
  await page.getByRole("button", { name: "Unblock client", exact: true }).waitFor();
  await waitForIdle();
  assert.match(await page.locator(".client").textContent(), /BLOCKED/);
  await page.getByRole("button", { name: "Unblock client", exact: true }).click();
  await page.getByRole("button", { name: "Block client", exact: true }).waitFor();
  await waitForIdle();
  assert.equal(count("POST /api/administration/blockClient"), 2);
  data = { ...data, clients: [{ ...automatic, onboarding: "dcr" }] };
  await page.reload();
  await page.locator(`[data-revoke="${automatic.client_id}"]`).waitFor();
  assert.match(await page.locator(".client").textContent(), /Dynamic registration/);
  assert.equal(await page.locator("[data-client-edit], [data-delete], [data-rotate]").count(), 0);

  // API keys preserve explicit scope selection and show plaintext only until acknowledged.
  const keyForm = page.locator("#key-create");
  await keyForm.locator('[name="name"]').fill("Automation key");
  await keyForm.locator('[name="key-scope"]').check();
  await keyForm.getByRole("button", { name: "Create API key", exact: true }).click();
  await page.locator("#credentials").filter({ hasText: "ca_fixture-once-only" }).waitFor();
  await waitForIdle();
  assert.equal(
    await page.locator("#credentials pre").textContent(),
    "Automation key\nca_fixture-once-only",
  );
  await page.getByRole("button", { name: "Disable key", exact: true }).click();
  await page.getByRole("button", { name: "Enable key", exact: true }).waitFor();
  await waitForIdle();
  await page.getByRole("button", { name: "Enable key", exact: true }).click();
  await page.getByRole("button", { name: "Disable key", exact: true }).waitFor();
  await waitForIdle();

  const retainedGrants = {
    ...machineKeys[0].permissions,
    "https://removed.example/api": ["read"],
  };

  machineKeys[0].permissions = retainedGrants;
  const keyEdit = page.locator('[data-key-rename="fixture-key"]');
  await keyEdit.locator("..").getByText("Rename key", { exact: true }).click();
  await keyEdit.locator('[name="name"]').fill("Renamed automation");
  await keyEdit.getByRole("button", { name: "Save name", exact: true }).click();
  await page.getByRole("heading", { name: "Renamed automation", exact: true }).waitFor();
  await waitForIdle();
  assert.deepEqual(keyUpdates.at(-1), { keyId: "fixture-key", name: "Renamed automation" });
  const grantsEdit = page.locator('[data-key-grants="fixture-key"]');
  await grantsEdit.locator("..").getByText("Edit grants", { exact: true }).click();
  await grantsEdit.getByRole("button", { name: "Save grants", exact: true }).click();
  await waitForIdle();
  assert.deepEqual(keyUpdates.at(-1), {
    keyId: "fixture-key",
    permissions: { [resource.identifier]: ["fixture:read"] },
  });

  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page
      .getByRole("heading", { name: "Renamed automation", exact: true })
      .scrollIntoViewIfNeeded();
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );

    if (process.env.DASHBOARD_SCREENSHOTS)
      await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOTS}/keys-${width}.png` });
  }

  // Undismissed credentials must disappear even when the post-delete read fails.
  assert.equal(await page.locator("#credentials").isVisible(), true);
  listResponse = async () => failed;
  await page.getByRole("button", { name: "Delete key", exact: true }).click();
  await page.getByRole("button", { name: "Retry refresh", exact: true }).waitFor();
  assert.equal(machineKeys.length, 0);
  assert.equal(await page.locator("#credentials").isVisible(), false);
  assert.equal(await page.getByText("ca_fixture-once-only", { exact: false }).count(), 0);
  listResponse = async () => ok(data);
  await page.getByRole("button", { name: "Retry refresh", exact: true }).click();
  await page.getByRole("heading", { name: "No API keys", exact: true }).waitFor();
  await waitForIdle();
  await keyForm.locator('[name="name"]').fill("Dismiss credentials");
  await keyForm.locator('[name="key-scope"]').check();
  await keyForm.getByRole("button", { name: "Create API key", exact: true }).click();
  await page.locator("#credentials").filter({ hasText: "ca_fixture-once-only" }).waitFor();
  await waitForIdle();
  await page.locator("#credentials button").click();
  assert.equal(await page.getByText("ca_fixture-once-only", { exact: false }).count(), 0);
  await page.getByRole("button", { name: "Delete key", exact: true }).click();
  await page.getByRole("heading", { name: "No API keys", exact: true }).waitFor();
  assert.equal(count("POST /api/administration/createApiKey"), 2);
  assert.equal(count("POST /api/administration/updateApiKey"), 4);
  assert.equal(count("POST /api/administration/deleteApiKey"), 2);

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
  // Observe navigation attempts, including a second attempt that cancels the first.
  // The auth client already follows its successful consent response.
  const protocol = await page.context().newCDPSession(page);
  await protocol.send("Page.enable");
  const navigations = [];
  protocol.on("Page.frameRequestedNavigation", (event) => {
    if (event.url === callback) navigations.push(event);
  });
  await page.route(`${origin}/api/auth/oauth2/consent`, (route) =>
    route.fulfill(ok({ redirect: true, url: callback })),
  );
  await page.route(callback, (route) =>
    route.fulfill({ status: 200, contentType: "text/html", body: "<h1>Application callback</h1>" }),
  );
  await page.getByRole("button", { name: "Allow access", exact: false }).click();
  await page.getByRole("heading", { name: "Application callback" }).waitFor();
  assert.equal(navigations.length, 1, "consent must navigate to the callback exactly once");
  await protocol.detach();
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
