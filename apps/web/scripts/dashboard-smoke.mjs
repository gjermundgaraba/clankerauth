import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import { chromium } from "playwright";
import { preview } from "vite";

// why: fail here on a missing build, not later on a page that preview cannot serve
await readFile(new URL("../dist/index.html", import.meta.url));

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
  const errors = [];
  page.on("dialog", async (dialog) => {
    errors.push(`Unexpected native dialog: ${dialog.message()}`);
    await dialog.dismiss();
  });
  page.on("pageerror", (error) => errors.push(error.message));
  const calls = [];
  const bodies = new Map();

  const resource = {
    builtIn: false,
    name: "Fixture API",
    identifier: "https://fixture.invalid/api",
    scopes: ["fixture:read"],
  };

  const automatic = {
    client_id: "https://client.fixture.invalid/metadata.json",
    client_name: "Automatic client",
    redirect_uris: ["https://fixture.invalid/callback"],
    token_endpoint_auth_method: "none",
    onboarding: "cimd",
    blocked: false,
  };

  const created = {
    client_id: "created-client",
    client_name: "Created client",
    redirect_uris: ["https://fixture.invalid/callback", "https://fixture.invalid/other"],
    token_endpoint_auth_method: "client_secret_basic",
  };

  const data = {
    email: "owner@fixture.invalid",
    issuer: origin,
    clients: [automatic],
    resources: [
      resource,
      {
        identifier: `${origin}/`,
        name: "clankerauth administration",
        scopes: ["clankerauth:read", "clankerauth:write"],
        builtIn: true,
      },
    ],
    clientAccess: [{ client_id: automatic.client_id, resource: resource.identifier }],
    connections: [
      {
        client_id: automatic.client_id,
        resource: resource.identifier,
        scopes: ["fixture:read"],
        approvedAt: "2026-09-10T12:00:00.000Z",
        refreshedAt: null,
      },
    ],
  };

  const ok = (body, status = 200) => ({ status, json: body });

  let isSignedIn = true;
  let machineKeys = [];
  let listResponse = async () => ok(data);
  let resourceResponse = () => ok(resource, 201);
  await page.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const key = `${request.method()} ${url.pathname}`;

    if (
      url.origin === origin &&
      (["/", "/resources", "/keys", "/login", "/consent"].includes(url.pathname) ||
        url.pathname.startsWith("/assets/"))
    ) {
      await route.continue();

      return;
    }

    calls.push(key);

    if (request.method() === "POST" && request.postData()) {
      bodies.set(key, [...(bodies.get(key) ?? []), request.postDataJSON()]);
    }

    let response;

    if (url.origin === origin) {
      switch (key) {
        case "POST /api/setupStatus":
          response = ok({ required: false });
          break;
        case "GET /api/auth/get-session":
          response = ok(
            isSignedIn
              ? {
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
                }
              : null,
          );
          break;
        case "POST /api/listApiKeys":
          response = ok({ keys: machineKeys });
          break;
        case "POST /api/createApiKey": {
          const key = {
            keyId: "fixture-key",
            ...request.postDataJSON(),
            enabled: true,
            createdAt: "2026-09-10T12:00:00.000Z",
          };

          machineKeys.push(key);
          response = ok({ ...key, key: "clankerauth_fixture-once-only" }, 201);
          break;
        }

        case "POST /api/updateApiKey": {
          const payload = request.postDataJSON();
          machineKeys = machineKeys.map((key) =>
            key.keyId === payload.keyId ? { ...key, ...payload } : key,
          );
          response = ok(machineKeys.find((key) => key.keyId === payload.keyId));
          break;
        }

        case "POST /api/deleteApiKey":
          machineKeys = [];
          response = ok({ deleted: true });
          break;
        case "POST /api/listClients":
          response = await listResponse();
          break;
        case "POST /api/createResource":
          response = resourceResponse();
          break;
        case "POST /api/createClient":
          response = ok({ ...created, client_secret: "fixture-first-secret" }, 201);
          break;
        case "GET /api/auth/oauth2/public-client":
          response = ok({ client_id: automatic.client_id, client_name: "<em>Client name</em>" });
          break;
        case "POST /api/revokeClient":
          response = ok({ revoked: true });
          break;
        case "POST /api/auth/sign-out":
          isSignedIn = false;
          response = ok({ success: true });
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
  const lastBody = (key) => bodies.get(key)?.at(-1);
  const credentials = page.locator("#credentials");
  const stored = page.getByRole("button", { name: "I've stored them", exact: true });
  const dialog = page.locator("dialog[open]");
  const headAction = page.locator(".page-head .page-acts button");
  const button = (name) => page.getByRole("button", { name, exact: true });
  const isHeld = async (target) => (await target.getAttribute("aria-disabled")) === "true";

  const waitForIdle = () =>
    page.waitForFunction(() => {
      const action = document.querySelector(".page-head .page-acts button");

      return action && action.getAttribute("aria-disabled") !== "true";
    });

  const assertModalWithFocus = async () => {
    await dialog.waitFor();
    await page.waitForFunction(() => {
      const open = document.querySelector("dialog[open]");

      return (
        open?.contains(document.activeElement) &&
        document.querySelector(".page-head")?.closest("[inert]") !== null
      );
    });
  };

  const showSection = async (label, heading) => {
    const loads = count("POST /api/setupStatus");
    await page
      .getByRole("navigation", { name: "Dashboard" })
      .getByRole("link", { name: new RegExp(`^${label}`) })
      .click();
    await page.getByRole("heading", { level: 1, name: heading, exact: true }).waitFor();
    assert.equal(count("POST /api/setupStatus"), loads);
  };

  const openForm = async (label) => {
    await page.locator(".page-head").getByRole("button", { name: label, exact: true }).click();
    await assertModalWithFocus();
  };

  const submitForm = (label) => dialog.getByRole("button", { name: label, exact: true }).click();

  const confirmChange = async (label) => {
    await assertModalWithFocus();
    await dialog.getByRole("button", { name: label, exact: true }).click();
    await dialog.waitFor({ state: "detached" });
    await waitForIdle();
  };

  // why: `dispatchEvent` skips Playwright's enabled check, so the press reaches the held control
  const pressHeld = async (target) => {
    assert.equal(await isHeld(target), true);
    await target.dispatchEvent("click");
    assert.equal(await dialog.count(), 0);
  };

  const checkbox = (scope, id) => scope.locator(`[role="checkbox"][aria-labelledby="${id}-label"]`);
  const tick = (id) => checkbox(dialog, id).click();

  await page.goto(origin);
  await page.getByRole("heading", { level: 1, name: "Clients", exact: true }).waitFor();
  await waitForIdle();

  await openForm("register client");
  await button("cancel").click();
  await dialog.waitFor({ state: "detached" });
  assert.equal(
    await page.evaluate(() => document.activeElement?.textContent?.includes("register client")),
    true,
  );

  const releaseList = Promise.withResolvers();
  listResponse = async () => {
    await releaseList.promise;

    return ok(data);
  };

  await openForm("register client");
  await dialog.locator("#form-name").fill(created.client_name);
  await dialog.locator("#form-redirect-uris").fill(created.redirect_uris.join("\n"));
  await tick(`form-resource-${resource.identifier}`);
  await dialog.locator("#form-auth-method").selectOption("client_secret_basic");

  const listStarted = page.waitForRequest(
    (request) =>
      request.method() === "POST" && new URL(request.url()).pathname === "/api/listClients",
  );

  await submitForm("register client");
  await listStarted;
  await dialog.waitFor({ state: "detached" });
  await pressHeld(headAction);
  releaseList.resolve();
  listResponse = async () => ok(data);
  await credentials.filter({ hasText: "fixture-first-secret" }).waitFor();
  await waitForIdle();
  assert.deepEqual(lastBody("POST /api/createClient"), {
    client_name: created.client_name,
    redirect_uris: created.redirect_uris,
    resources: [resource.identifier],
    application_type: "web",
    token_endpoint_auth_method: "client_secret_basic",
  });
  await stored.click();
  await credentials.waitFor({ state: "detached" });

  await button(`Revoke ${resource.name}`).click();
  await confirmChange("revoke");
  await button(`revoke all ${automatic.client_name}`).click();
  await confirmChange("revoke");
  assert.deepEqual(bodies.get("POST /api/revokeClient"), [
    { client_id: automatic.client_id, resource: resource.identifier },
    { client_id: automatic.client_id },
  ]);

  await showSection("resources", "Resources");

  const unservable =
    "Resource identifiers must be absolute URIs in canonical form, without a fragment";

  resourceResponse = () => ({
    status: 400,
    json: new Action.InvalidInput({
      message: unservable,
      issues: [{ path: ["identifier"], message: unservable }],
    }),
  });
  await openForm("add resource");
  await dialog.locator("#form-name").fill("Second API");
  await dialog.locator("#form-identifier").fill("https://fixture.invalid/second");
  await dialog.locator("#form-scopes").fill("fixture:read fixture:write");
  await submitForm("add resource");
  await dialog.getByText(unservable).waitFor();
  resourceResponse = () => ok(resource, 201);
  await submitForm("add resource");
  await dialog.waitFor({ state: "detached" });
  await waitForIdle();
  assert.deepEqual(bodies.get("POST /api/createResource"), [
    {
      identifier: "https://fixture.invalid/second",
      name: "Second API",
      scopes: ["fixture:read", "fixture:write"],
    },
    {
      identifier: "https://fixture.invalid/second",
      name: "Second API",
      scopes: ["fixture:read", "fixture:write"],
    },
  ]);

  await showSection("api keys", "API keys");
  await openForm("create key");
  await dialog.locator("#form-name").fill("Automation key");
  await tick(`form-grant-${resource.identifier}-fixture:read`);
  await submitForm("create key");
  await credentials.filter({ hasText: "clankerauth_fixture-once-only" }).waitFor();
  await waitForIdle();
  assert.deepEqual(lastBody("POST /api/createApiKey"), {
    name: "Automation key",
    permissions: { [resource.identifier]: ["fixture:read"] },
    expiresAt: null,
  });

  await button("disable Automation key").click();
  await button("enable Automation key").waitFor();
  await waitForIdle();
  assert.deepEqual(lastBody("POST /api/updateApiKey"), { keyId: "fixture-key", enabled: false });

  machineKeys[0].permissions = {
    ...machineKeys[0].permissions,
    "https://removed.example/api": ["read"],
  };
  await button("rename Automation key").click();
  await assertModalWithFocus();
  await dialog.locator("#form-name").fill("Renamed automation");
  await submitForm("save name");
  await dialog.waitFor({ state: "detached" });
  await waitForIdle();
  assert.deepEqual(lastBody("POST /api/updateApiKey"), {
    keyId: "fixture-key",
    name: "Renamed automation",
  });

  await button("edit grants Renamed automation").click();
  await assertModalWithFocus();
  await submitForm("save grants");
  await dialog.waitFor({ state: "detached" });
  await waitForIdle();
  assert.deepEqual(lastBody("POST /api/updateApiKey"), {
    keyId: "fixture-key",
    permissions: { [resource.identifier]: ["fixture:read"] },
  });

  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    assert.equal(await button("Sign out").isVisible(), true);

    if (process.env.DASHBOARD_SCREENSHOTS)
      await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOTS}/keys-${width}.png` });
  }

  await button("delete Renamed automation").click();
  await confirmChange("delete");
  await page.getByText("No API keys", { exact: true }).waitFor();
  assert.deepEqual(lastBody("POST /api/deleteApiKey"), { keyId: "fixture-key" });

  await page.reload();
  await page.getByRole("heading", { level: 1, name: "API keys", exact: true }).waitFor();
  await page.goto(`${origin}/resources`);
  await page.getByRole("heading", { level: 1, name: "Resources", exact: true }).waitFor();
  await waitForIdle();

  await button("Sign out").click();
  await page.waitForURL(`${origin}/login`);
  await page.getByRole("heading", { name: "Sign in to clankerauth", exact: true }).waitFor();
  assert.equal(count("POST /api/auth/sign-out"), 1);

  const callback = "http://127.0.0.1:43129/callback";
  await page.goto(
    `${origin}/consent?${new URLSearchParams({ client_id: automatic.client_id, redirect_uri: callback, resource: resource.identifier, scope: "offline_access fixture:read", sig: "fixture" })}`,
  );
  await page.getByRole("heading", { name: "Allow this connection?" }).waitFor();
  const main = page.locator("main");
  await main.getByText("<em>Client name</em>").first().waitFor();
  const consent = await main.textContent();
  assert.ok(consent.includes(automatic.client_id));
  assert.ok(consent.includes("Client metadata host: client.fixture.invalid"));
  assert.ok(consent.includes(callback));
  assert.equal(await main.locator("em").count(), 0);
  // why: CDP sees every navigation attempt, including a second one that would cancel the first
  const protocol = await page.context().newCDPSession(page);
  await protocol.send("Page.enable");
  const navigations = [];
  protocol.on("Page.frameRequestedNavigation", (event) => {
    if (event.url === callback) navigations.push(event);
  });
  const approvals = [];
  await page.route(`${origin}/api/auth/oauth2/consent`, (route) => {
    approvals.push(route.request().postDataJSON());

    return route.fulfill(ok({ redirect: true, url: callback }));
  });
  await checkbox(main, "consent-scope-offline_access").click();
  await page.route(callback, (route) =>
    route.fulfill({ status: 200, contentType: "text/html", body: "<h1>Application callback</h1>" }),
  );
  await button("allow access").click();
  await page.getByRole("heading", { name: "Application callback" }).waitFor();
  assert.equal(navigations.length, 1, "consent must navigate to the callback exactly once");
  assert.deepEqual(approvals, [{ accept: true, scope: "fixture:read" }]);
  await protocol.detach();
  assert.deepEqual(errors, []);
  console.log("Dashboard browser checks passed.");
} finally {
  try {
    await browser?.close();
  } finally {
    await new Promise((resolve, reject) =>
      server.httpServer.close((error) => (error ? reject(error) : resolve())),
    );
  }
}
