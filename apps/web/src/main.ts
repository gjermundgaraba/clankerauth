import { createAuthClient } from "better-auth/client";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import {
  Http,
  type Client,
  type ClientCredentials,
  type MachineKey,
  type ResourceSummary,
} from "@clankerauth/api";
import { Effect } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import "./style.css";

type ClientView = typeof Client.Type;
type ResourceView = typeof ResourceSummary.Type;
type KeyView = typeof MachineKey.Type;

const api = await Effect.runPromise(
  Http.client({ baseUrl: location.origin }).pipe(Effect.provide(FetchHttpClient.layer)),
);

function request<A, E>(effect: Effect.Effect<A, E>): Promise<A> {
  return Effect.runPromise(
    effect.pipe(
      Effect.mapError(
        (error) =>
          new Error(
            typeof error === "object" &&
              error !== null &&
              "error" in error &&
              typeof error.error === "string"
              ? error.error
              : "Request could not be completed. Please try again.",
          ),
      ),
    ),
  );
}

const auth = createAuthClient({ plugins: [oauthProviderClient()] });
const app = document.querySelector<HTMLDivElement>("#app")!;
app.innerHTML = `<header><a href="/" class="brand"><span class="mark">c.</span> clanker<span class="muted">auth</span></a><span class="tag">PRIVATE IDENTITY</span></header><main id="main"></main><footer>Local accounts. Explicit access.<span>Self-hosted authorization server</span></footer>`;
const main = document.querySelector<HTMLElement>("#main")!;
const escape = (text: string) =>
  text.replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!,
  );
function message(text: string) {
  const target = document.querySelector<HTMLElement>("#message")!;
  target.textContent = text;
  if (text && target.hasAttribute("tabindex")) {
    target.focus();
    target.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}
let submitting = false;
async function submit(task: () => Promise<void>) {
  if (submitting) return;
  submitting = true;
  const buttons = Array.from(main.querySelectorAll("button"), (button) => ({
    button,
    disabled: button.disabled,
  }));
  buttons.forEach(({ button }) => (button.disabled = true));
  message("");
  try {
    await task();
  } catch (error) {
    message(error instanceof Error ? error.message : "Request failed");
  } finally {
    buttons.forEach(({ button, disabled }) => (button.disabled = disabled));
    submitting = false;
  }
}
function confirmed(prompt: string, task: () => Promise<void>) {
  if (submitting || !confirm(prompt)) return;
  void submit(task);
}

function setup() {
  main.innerHTML = `<section class="intro"><p class="eyebrow">YOUR NETWORK, YOUR IDENTITY</p><h1>Your identity.<br>Starts here.</h1><p>Create the owner account for your private applications.<br>Your account stays on your infrastructure.</p><div class="note"><span class="dot"></span> One owner · Explicit access</div></section>
    <section class="card login"><p class="eyebrow">FIRST-TIME SETUP</p><h2>Create your account</h2><p class="muted">This account manages Clients and Resources and approves access.</p>
    <form id="setup"><label>Email<input name="email" type="email" autocomplete="username" required placeholder="owner@example.internal"></label>
    <label>Password<input name="password" type="password" autocomplete="new-password" required minlength="8" maxlength="128" aria-describedby="password-help"></label><p id="password-help" class="help">Use 8–128 characters. Save your password somewhere safe.</p>
    <label>Confirm password<input name="confirmation" type="password" autocomplete="new-password" required minlength="8" maxlength="128"></label>
    <p id="message" role="alert"></p><button>Create account <span>→</span></button></form></section>`;
  const form = document.querySelector<HTMLFormElement>("#setup")!;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submit(async () => {
      const password = form.querySelector<HTMLInputElement>('[name="password"]')!.value;
      const confirmation = form.querySelector<HTMLInputElement>('[name="confirmation"]')!.value;
      if (password.length < 8 || password.length > 128)
        throw new Error("Use a password between 8 and 128 characters.");
      if (password !== confirmation) throw new Error("Passwords do not match.");
      await request(
        api
          .setupOwner({
            email: form.querySelector<HTMLInputElement>('[name="email"]')!.value,
            password,
          })
          .pipe(
            Effect.tap(() => Effect.sync(() => location.replace("/login?setup=complete"))),
            Effect.catchTag("Conflict", () => Effect.sync(() => location.replace("/login"))),
          ),
      );
    });
  });
}

function login() {
  main.innerHTML = `<section class="intro"><p class="eyebrow">YOUR NETWORK, YOUR IDENTITY</p><h1>One identity.<br>Deliberate access.</h1><p>Sign in to authorize your private applications.<br>Your account stays on your infrastructure.</p><div class="note"><span class="dot"></span> Password login · No external identity provider</div></section>
    <section class="card login"><p class="eyebrow">OWNER ACCESS</p><h2>Welcome back</h2><p class="muted">Use your local account to continue.</p>
    <form id="login"><label>Email<input name="email" type="email" autocomplete="username" required placeholder="owner@example.internal"></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
    <p id="message" role="alert"></p><button>Sign in <span>→</span></button></form></section>`;
  const form = document.querySelector<HTMLFormElement>("#login")!;
  if (new URLSearchParams(location.search).get("setup") === "complete") {
    const confirmation = document.createElement("p");
    confirmation.setAttribute("role", "status");
    confirmation.textContent = "Account created. Sign in to continue.";
    form.before(confirmation);
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submit(async () => {
      const result = await auth.signIn.email({
        email: form.querySelector<HTMLInputElement>('[name="email"]')!.value,
        password: form.querySelector<HTMLInputElement>('[name="password"]')!.value,
      });
      if (result.error)
        throw new Error("Sign-in failed. Check your credentials or try again later.");
      // The provider client handles OAuth redirects; a plain login returns to the dashboard.
      if (!new URLSearchParams(location.search).has("sig")) location.assign("/");
    });
  });
}

async function consent() {
  const query = new URLSearchParams(location.search);
  const clientId = query.get("client_id");
  if (!clientId || !query.has("sig"))
    throw new Error("Start authorization from your application; this consent link is incomplete.");
  const client = await auth.oauth2.publicClient({ query: { client_id: clientId } });
  if (client.error || !client.data)
    throw new Error("Sign in through your application to continue authorization.");
  const scopes = (query.get("scope") ?? "").split(" ").filter(Boolean);
  const resources = query.getAll("resource");
  let metadataHost: string | undefined;
  try {
    const identifier = new URL(clientId);
    if (identifier.protocol === "https:") metadataHost = identifier.hostname;
  } catch {
    // Registered identifiers need not be URLs.
  }
  const redirect = query.get("redirect_uri");
  main.className = "center";
  main.innerHTML = `<section class="card consent"><p class="eyebrow">PERMISSION REQUEST</p><h1>Allow this connection?</h1>
    <p><strong>${escape(client.data.client_name ?? clientId)}</strong> wants to act on your behalf.</p>
    ${metadataHost ? `<p>Client metadata host: <strong>${escape(metadataHost)}</strong></p>` : ""}
    <label>Client ID<code>${escape(clientId)}</code></label>
    <label>Callback destination<code>${escape(redirect ?? "Not supplied in this request")}</code></label>
    <p class="help">The client supplies its display name. Review the identifier and callback before approving.</p>
    <div class="resource"><span class="eyebrow">ONLY FOR THIS RESOURCE</span>${resources.map((r) => `<code>${escape(r)}</code>`).join("")}</div>
    <h3>Requested access</h3><ul class="scopes">${scopes.map((scope) => `<li><span>✓</span><code>${escape(scope)}</code></li>`).join("")}</ul>
    ${query.has("claims") ? `<h3>Additional identity claims</h3><pre>${escape(query.get("claims")!)}</pre>` : ""}
    <p class="help">Access tokens expire after five minutes. Offline access lets the Client renew them until you revoke its authorization.</p>
    <p id="message" role="alert"></p><form id="consent"><div class="actions"><button type="submit" name="decision" value="deny" class="secondary">Deny</button><button type="submit" name="decision" value="allow">Allow access →</button></div></form></section>`;
  const form = document.querySelector<HTMLFormElement>("#consent")!;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const accept = (event.submitter as HTMLButtonElement).value === "allow";
    void submit(async () => {
      const result = await auth.oauth2.consent({ accept });
      if (result.error)
        throw new Error("Authorization could not be completed. Restart from your application.");
      // Better Auth follows the redirect; a second navigation would cancel the callback.
    });
  });
}

function textField(fields: FormData, name: string): string {
  const value = fields.get(name);
  if (typeof value !== "string") throw new Error(`Missing form field: ${name}`);
  return value.trim();
}

function selectedResources(form: HTMLFormElement): string[] {
  return Array.from(
    form.querySelectorAll<HTMLInputElement>('input[name="resources"]:checked'),
    (input) => input.value,
  );
}

function resourceFields(fields: FormData) {
  const scopes = [...new Set(textField(fields, "scopes").split(/\s+/).filter(Boolean))];
  if (!scopes.length) throw new Error("Add at least one custom Scope.");
  return { name: textField(fields, "name"), scopes };
}

function keyGrants(form: HTMLFormElement) {
  const grants: Record<string, string[]> = {};
  for (const checkbox of form.querySelectorAll<HTMLInputElement>('input[name="key-scope"]:checked'))
    (grants[checkbox.dataset.resource!] ??= []).push(checkbox.value);
  return grants;
}

// One-time credentials stay in memory until the owner dismisses them.
// A later rotation replaces the now-invalid secret for the same Client.
const pendingKeys = new Map<string, string>();
const pendingCredentials = new Map<string, typeof ClientCredentials.Type>();
function renderCredentials() {
  const box = document.querySelector<HTMLElement>("#credentials")!;
  box.classList.toggle("hidden", pendingCredentials.size === 0 && pendingKeys.size === 0);
  box.replaceChildren();
  if (!pendingCredentials.size && !pendingKeys.size) return;
  box.innerHTML = `<h2>Save these credentials now</h2><p>API keys and client secrets are shown only once.</p><button class="secondary">Saved — dismiss credentials</button>`;
  const button = box.querySelector("button")!;
  for (const value of pendingCredentials.values()) {
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(value, null, 2);
    button.before(pre);
  }
  for (const value of pendingKeys.values()) {
    const pre = document.createElement("pre");
    pre.textContent = value;
    button.before(pre);
  }
  button.addEventListener("click", () => {
    pendingKeys.clear();
    pendingCredentials.clear();
    renderCredentials();
  });
}
function showCredentials() {
  renderCredentials();
  document.querySelector("#credentials")!.scrollIntoView({ behavior: "smooth" });
}

// The write has already succeeded. A failed read must never invite replaying it.
async function refreshDashboard() {
  try {
    await dashboard();
  } catch {
    document.querySelector<HTMLFieldSetElement>("#dashboard-mutations")!.disabled = true;
    message("Saved, but the dashboard could not refresh.");
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "secondary";
    retry.textContent = "Retry refresh";
    retry.addEventListener("click", () => {
      void submit(refreshDashboard);
    });
    document.querySelector("#message")!.append(" ", retry);
  }
}

const scopeHelp =
  "Separate scopes with spaces. openid, profile, email and offline_access are reserved.";
const onboardingLabel = {
  managed: "Managed registration · first party, no consent screen",
  dcr: "Dynamic registration",
  cimd: "Client ID Metadata Document",
};
const isManaged = (client: ClientView) => !client.onboarding || client.onboarding === "managed";

const columns = (title: string, count: number, intro: string, list: string, form: string) =>
  `<div class="columns dashboard-section"><section><h2>${title} <span class="count">${count}</span></h2><p class="muted">${intro}</p>${list}</section><section class="card registration">${form}</section></div>`;
const empty = (title: string, text: string) =>
  `<div class="empty"><h3>${title}</h3><p>${text}</p></div>`;
const resourceSummary = (resource: ResourceView) =>
  `<code>${escape(resource.identifier)}</code><span class="muted">${escape(resource.scopes.join(" · "))}</span>`;
const resourceChoices = (resources: readonly ResourceView[], selected: readonly string[]) =>
  resources
    .map(
      (resource) =>
        `<label class="checkbox resource-choice"><input type="checkbox" name="resources" value="${escape(resource.identifier)}" ${selected.includes(resource.identifier) ? "checked" : ""}><span>${escape(resource.name)}${resourceSummary(resource)}</span></label>`,
    )
    .join("");
const keyChoices = (
  resources: readonly ResourceView[],
  grants: Record<string, readonly string[]>,
) =>
  resources
    .map(
      (resource) =>
        `<fieldset><legend>${escape(resource.name)}</legend><code>${escape(resource.identifier)}</code>${resource.scopes
          .map(
            (scope) =>
              `<label class="checkbox"><input type="checkbox" name="key-scope" data-resource="${escape(resource.identifier)}" value="${escape(scope)}" ${grants[resource.identifier]?.includes(scope) ? "checked" : ""}><code>${escape(scope)}</code></label>`,
          )
          .join("")}</fieldset>`,
    )
    .join("") || '<p class="help">Add a Resource to grant access.</p>';

const resourceCard = (resource: ResourceView, dependents: readonly ClientView[]) =>
  `<article class="resource"><h3>${escape(resource.name)}</h3>${resourceSummary(resource)}
  <p class="help dependencies">Managed Clients with access: ${dependents.length ? dependents.map((client) => escape(client.client_name ?? client.client_id)).join(", ") : "None"}</p>
  ${resource.builtIn ? '<p class="help">Built-in administration resource. OAuth access tokens are required; its scopes and identifier are fixed.</p>' : ""}
  <details><summary>Edit resource</summary><form data-resource-edit="${escape(resource.identifier)}"><label>Name<input name="name" value="${escape(resource.name)}" required maxlength="100"></label>
  ${resource.builtIn ? "" : `<label>Scopes<input name="scopes" required value="${escape(resource.scopes.join(" "))}"></label><p class="help">Added scopes need new consent. Removed scopes are no longer issued, but stored grants are kept and work again if the scope is restored.</p>`}
  <button>Save resource</button></form></details>
  ${resource.builtIn ? "" : `<button class="danger" data-resource-delete="${escape(resource.identifier)}">Delete resource</button>`}</article>`;
const resourceForm = () =>
  `<h2>Add resource</h2><form id="resource-create"><label>Name<input name="name" required maxlength="100" placeholder="Notes MCP"></label><label>HTTP or HTTPS identifier<input name="identifier" type="url" required placeholder="https://notes.internal/mcp"></label><p class="help">The identifier is the token audience and cannot be changed later.</p><label>Scopes<input name="scopes" required placeholder="notes:read notes:write"></label><p class="help">${scopeHelp}</p><button>Add resource +</button></form>`;

const keyCard = (key: KeyView, resources: readonly ResourceView[]) =>
  `<article class="resource"><h3>${escape(key.name)}</h3><p>${key.enabled ? "Enabled" : "Disabled"} · ${key.expiresAt ? `Expires ${escape(new Date(key.expiresAt).toLocaleString())}` : "Valid until revoked"}</p>${Object.entries(
    key.permissions,
  )
    .map(
      ([resource, scopes]) =>
        `<code>${escape(resource)}</code><p class="help">${escape(scopes.join(" · "))}</p>`,
    )
    .join("")}
  <details><summary>Rename key</summary><form data-key-rename="${escape(key.keyId)}"><label>Name<input name="name" required maxlength="100" value="${escape(key.name)}"></label><button>Save name</button></form></details>
  <details><summary>Edit grants</summary><form data-key-grants="${escape(key.keyId)}">${keyChoices(resources, key.permissions)}<p class="help">Saving replaces all grants, including any not currently available, with the selected scopes.</p><button>Save grants</button></form></details>
  <div class="actions"><button class="secondary" data-key-toggle="${escape(key.keyId)}" data-enabled="${key.enabled}">${key.enabled ? "Disable key" : "Enable key"}</button><button class="danger" data-key-delete="${escape(key.keyId)}">Delete key</button></div></article>`;
const keyForm = (resources: readonly ResourceView[]) =>
  `<h2>Create API key</h2><form id="key-create"><label>Name<input name="name" required maxlength="100" placeholder="Backup script"></label>${keyChoices(resources, {})}<label>Expiry (optional)<input name="expiry" type="datetime-local"></label><p class="help">At most one year ahead; blank means valid until revoked. The key is shown once.</p><button ${resources.length ? "" : "disabled"}>Create API key</button></form>`;

const clientCard = (
  client: ClientView,
  resources: readonly ResourceView[],
  allowed: readonly string[],
) => {
  const managed = isManaged(client);
  const id = escape(client.client_id);
  const eligible = managed
    ? resources
        .filter((resource) => allowed.includes(resource.identifier))
        .map(
          (resource) =>
            `<div class="allowed-resource"><strong>${escape(resource.name)}</strong>${resourceSummary(resource)}</div>`,
        )
        .join("") || '<p class="help">No Resource access configured.</p>'
    : '<p class="help">Any configured Resource. Each needs your consent.</p>';
  const access = managed
    ? `<details><summary>Manage access</summary><form data-client-access="${id}"><fieldset><legend>Allowed Resources</legend>${resourceChoices(resources, allowed) || '<p class="help">Add a Resource above to configure access.</p>'}</fieldset><p class="help">Removing access stops new authorization and refresh; use Revoke authorization to clear issued grants.</p><button>Save access</button></form></details>`
    : "";
  const actions = [
    `<button class="secondary" data-revoke="${id}">Revoke authorization</button>`,
    `<button class="secondary" data-block="${id}" data-blocked="${client.blocked ? "true" : "false"}">${client.blocked ? "Unblock client" : "Block client"}</button>`,
    managed && client.token_endpoint_auth_method !== "none"
      ? `<button class="secondary" data-rotate="${id}">Rotate secret</button>`
      : "",
    managed ? `<button class="danger" data-delete="${id}">Delete client</button>` : "",
  ].join("");
  return `<article class="card client"><div class="client-heading"><h3>${escape(client.client_name ?? "Unnamed client")}</h3><span class="tag">${client.token_endpoint_auth_method === "none" ? "PUBLIC · PKCE" : "CONFIDENTIAL · PKCE"}</span></div><p class="help">${onboardingLabel[client.onboarding ?? "managed"]}${client.blocked ? " · BLOCKED" : ""}</p><label>Client ID<code>${id}</code></label><label>Redirect URI<code>${escape(client.redirect_uris.join(", "))}</code></label>
  <h3>${managed ? "Allowed Resources" : "Resources eligible for consent"}</h3>${eligible}${access}<div class="actions">${actions}</div></article>`;
};
const registerForm = (resources: readonly ResourceView[]) =>
  `<p class="eyebrow">MANAGED REGISTRATION</p><h2>Register client</h2><form id="register"><fieldset><label>Client name<input name="name" required maxlength="100" placeholder="My MCP client"></label><label>Exact redirect URI<input name="redirect" type="url" required placeholder="https://app.internal/callback"></label><fieldset><legend>Allowed Resources (optional)</legend>${resourceChoices(resources, []) || '<p class="help">You can configure Resource access after registration.</p>'}</fieldset><label class="checkbox"><input type="checkbox" name="native">Native / desktop client (loopback redirect)</label><label class="checkbox"><input type="checkbox" name="confidential">Confidential client (can securely store a secret)</label><button>Register client +</button></fieldset><p class="help">S256 PKCE is always required. Clients you register here are first party and skip the consent screen.</p></form>`;

async function dashboard() {
  const [data, keyData] = await Promise.all([
    request(api.listClients()),
    request(api.listApiKeys()),
  ]);
  const { resources } = data;
  const keyResources = resources.filter((resource) => !resource.builtIn);
  const allowed = (clientId: string) =>
    data.clientAccess
      .filter((access) => access.client_id === clientId)
      .map((access) => access.resource);
  main.className = "dashboard";
  main.innerHTML = `
    <div class="page-title"><div><p class="eyebrow">CONTROL PLANE</p><h1>Clients and Resources</h1><p class="muted">Signed in as ${escape(data.email)}</p></div><button id="logout" class="secondary">Sign out</button></div>
    <div class="issuer"><span class="dot"></span><span>Canonical issuer</span><code>${escape(data.issuer)}</code></div>
    <p id="message" role="alert" tabindex="-1"></p>
    <section id="credentials" class="card hidden" aria-live="polite"></section>
    <fieldset id="dashboard-mutations" aria-label="Clients and Resources">
    ${columns(
      "Resources",
      resources.length,
      "Protected APIs and MCP servers, and the scopes they define.",
      resources
        .map((resource) =>
          resourceCard(
            resource,
            data.clients.filter(
              (client) =>
                isManaged(client) && allowed(client.client_id).includes(resource.identifier),
            ),
          ),
        )
        .join("") ||
        empty(
          "Add your first Resource",
          "Define a protected API or MCP server. Compatible MCP clients onboard automatically when you connect.",
        ),
      resourceForm(),
    )}
    ${columns(
      "API keys",
      keyData.keys.length,
      "Direct access for CLIs and automation. Keys carry only the scopes you select, filtered by current Resource policy. Policy changes do not revoke stored grants; restoring policy restores access.",
      keyData.keys.map((key) => keyCard(key, keyResources)).join("") ||
        empty("No API keys", "Create a key for a CLI or automation that needs direct access."),
      keyForm(keyResources),
    )}
    ${columns(
      "Clients",
      data.clients.length,
      "Compatible MCP clients register themselves when they connect; registration alone grants no access. Revoking and blocking take effect immediately for this server’s administration MCP. Other resource servers may accept issued access tokens for up to five minutes.",
      data.clients
        .map((client) => clientCard(client, resources, allowed(client.client_id)))
        .join("") ||
        empty(
          "No Clients registered",
          "Connect your MCP client to a configured server to onboard automatically, or register a managed Client here.",
        ),
      registerForm(resources),
    )}
    </fieldset>`;
  renderCredentials();

  const form = (id: string) => document.querySelector<HTMLFormElement>(id)!;
  const onSubmit = (target: HTMLFormElement, task: (form: HTMLFormElement) => Promise<void>) =>
    target.addEventListener("submit", (event) => {
      event.preventDefault();
      void submit(() => task(target));
    });
  const onClick = (selector: string, handler: (button: HTMLButtonElement) => void) => {
    for (const button of main.querySelectorAll<HTMLButtonElement>(selector))
      button.addEventListener("click", () => handler(button));
  };

  document.querySelector("#logout")!.addEventListener("click", () => {
    void submit(async () => {
      await auth.signOut();
      location.assign("/login");
    });
  });
  onSubmit(form("#register"), async (target) => {
    const fields = new FormData(target);
    const result = await request(
      api.createClient({
        name: textField(fields, "name"),
        redirect: textField(fields, "redirect"),
        resources: selectedResources(target),
        native: fields.has("native"),
        confidential: fields.has("confidential"),
      }),
    );
    target.reset();
    pendingCredentials.set(result.client_id, result);
    showCredentials();
    await refreshDashboard();
  });
  onSubmit(form("#key-create"), async (target) => {
    const fields = new FormData(target);
    const expiry = textField(fields, "expiry");
    const result = await request(
      api.createApiKey({
        name: textField(fields, "name"),
        permissions: keyGrants(target),
        expiresAt: expiry ? new Date(expiry).toISOString() : null,
      }),
    );
    pendingKeys.set(result.keyId, `${result.name}\n${result.key}`);
    target.reset();
    showCredentials();
    await refreshDashboard();
  });
  onSubmit(form("#resource-create"), async (target) => {
    const fields = new FormData(target);
    await request(
      api.createResource({
        identifier: textField(fields, "identifier"),
        ...resourceFields(fields),
      }),
    );
    target.reset();
    await refreshDashboard();
  });
  for (const edit of main.querySelectorAll<HTMLFormElement>("[data-key-rename]"))
    onSubmit(edit, async (target) => {
      await request(
        api.updateApiKey({
          keyId: target.dataset.keyRename!,
          name: textField(new FormData(target), "name"),
        }),
      );
      await refreshDashboard();
    });
  for (const edit of main.querySelectorAll<HTMLFormElement>("[data-key-grants]"))
    onSubmit(edit, async (target) => {
      await request(
        api.updateApiKey({
          keyId: target.dataset.keyGrants!,
          permissions: keyGrants(target),
        }),
      );
      await refreshDashboard();
    });
  for (const edit of main.querySelectorAll<HTMLFormElement>("[data-resource-edit]"))
    onSubmit(edit, async (target) => {
      const resource = resources.find(
        (resource) => resource.identifier === target.dataset.resourceEdit,
      )!;
      await request(
        api.updateResource({
          identifier: target.dataset.resourceEdit!,
          name: textField(new FormData(target), "name"),
          scopes: resource.builtIn ? resource.scopes : resourceFields(new FormData(target)).scopes,
        }),
      );
      await refreshDashboard();
    });
  for (const edit of main.querySelectorAll<HTMLFormElement>("[data-client-access]"))
    edit.addEventListener("submit", (event) => {
      event.preventDefault();
      const client_id = edit.dataset.clientAccess!;
      const selected = selectedResources(edit);
      const removed = allowed(client_id).filter((resource) => !selected.includes(resource));
      const save = async () => {
        await request(api.setClientAccess({ client_id, resources: selected }));
        await refreshDashboard();
      };
      if (removed.length)
        confirmed(
          `Remove access to ${removed.join(", ")}? Stored consent remains until revoked.`,
          save,
        );
      else void submit(save);
    });
  onClick("[data-key-toggle]", (button) => {
    void submit(async () => {
      await request(
        api.updateApiKey({
          keyId: button.dataset.keyToggle!,
          enabled: button.dataset.enabled !== "true",
        }),
      );
      await refreshDashboard();
    });
  });
  onClick("[data-key-delete]", (button) => {
    const keyId = button.dataset.keyDelete!;
    confirmed("Delete this API key?", async () => {
      await request(api.deleteApiKey({ keyId }));
      pendingKeys.delete(keyId);
      renderCredentials();
      await refreshDashboard();
    });
  });
  onClick("[data-revoke]", (button) => {
    const client_id = button.dataset.revoke!;
    confirmed("Revoke this Client’s authorization? It can request consent again.", async () => {
      await request(api.revokeClient({ client_id }));
      await refreshDashboard();
    });
  });
  onClick("[data-block]", (button) => {
    const client_id = button.dataset.block!;
    const blocked = button.dataset.blocked !== "true";
    confirmed(
      blocked ? "Block this Client and revoke its authorization?" : "Unblock this Client?",
      async () => {
        await request(api.blockClient({ client_id, blocked }));
        await refreshDashboard();
      },
    );
  });
  onClick("[data-rotate]", (button) => {
    const client_id = button.dataset.rotate!;
    confirmed("Rotate the secret? The old one stops working immediately.", async () => {
      const result = await request(api.rotateClientSecret({ client_id }));
      pendingCredentials.set(result.client_id, result);
      showCredentials();
    });
  });
  onClick("[data-delete]", (button) => {
    const client_id = button.dataset.delete!;
    confirmed("Delete this Client and its grants?", async () => {
      await request(api.deleteClient({ client_id }));
      pendingCredentials.delete(client_id);
      renderCredentials();
      await refreshDashboard();
    });
  });
  onClick("[data-resource-delete]", (button) => {
    const identifier = button.dataset.resourceDelete!;
    confirmed(
      `Delete Resource ${identifier}? Stored grants are kept and may become usable again if it is recreated.`,
      async () => {
        await request(api.deleteResource({ identifier }));
        await refreshDashboard();
      },
    );
  });
}

try {
  const state = await request(api.setupStatus());
  if (state.required) {
    if (location.pathname !== "/setup") location.replace("/setup");
    else setup();
  } else if (location.pathname === "/setup") {
    const session = await auth.getSession();
    location.replace(session.data ? "/" : "/login");
  } else if (location.pathname === "/consent") await consent();
  else {
    const session = await auth.getSession();
    if (!session.data || location.pathname === "/login") login();
    else await dashboard();
  }
} catch (error) {
  main.innerHTML = `<section class="card"><h1>Unable to continue</h1><p>${escape(error instanceof Error ? error.message : "Please try again")}</p><a href="/login">Return to sign in</a></section>`;
}
