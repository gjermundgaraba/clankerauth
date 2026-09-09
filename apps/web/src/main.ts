import { createAuthClient } from "better-auth/client";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { Api, type ClientCredentials } from "@clankerauth/api";
import { Effect } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { HttpApiClient } from "effect/unstable/httpapi";
import "./style.css";

const api = await Effect.runPromise(
  HttpApiClient.make(Api, { baseUrl: location.origin }).pipe(Effect.provide(FetchHttpClient.layer)),
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

function setup() {
  main.innerHTML = `<section class="intro"><p class="eyebrow">YOUR NETWORK, YOUR IDENTITY</p><h1>Your identity.<br>Starts here.</h1><p>Create the owner account for your private applications.<br>Your account stays on your infrastructure.</p><div class="note"><span class="dot"></span> One owner · Explicit access</div></section><section class="card login"><p class="eyebrow">FIRST-TIME SETUP</p><h2>Create your account</h2><p class="muted">This account manages Clients and Resources and approves access.</p><form id="setup"><label>Email<input name="email" type="email" autocomplete="username" required placeholder="owner@example.internal"></label><label>Password<input name="password" type="password" autocomplete="new-password" required minlength="8" maxlength="128" aria-describedby="password-help"></label><p id="password-help" class="help">Use 8–128 characters. Save your password somewhere safe.</p><label>Confirm password<input name="confirmation" type="password" autocomplete="new-password" required minlength="8" maxlength="128"></label><p id="message" role="alert"></p><button>Create account <span>→</span></button></form></section>`;
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
        api.setup
          .create({
            payload: {
              email: form.querySelector<HTMLInputElement>('[name="email"]')!.value,
              password,
            },
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
  main.innerHTML = `<section class="intro"><p class="eyebrow">YOUR NETWORK, YOUR IDENTITY</p><h1>One identity.<br>Deliberate access.</h1><p>Sign in to authorize your private applications.<br>Your account stays on your infrastructure.</p><div class="note"><span class="dot"></span> Password login · No external identity provider</div></section><section class="card login"><p class="eyebrow">OWNER ACCESS</p><h2>Welcome back</h2><p class="muted">Use your local account to continue.</p><form id="login"><label>Email<input name="email" type="email" autocomplete="username" required placeholder="owner@example.internal"></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><p id="message" role="alert"></p><button>Sign in <span>→</span></button></form></section>`;
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
      // The provider client handles OAuth redirects; normal local login returns to administration.
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
  main.className = "center";
  main.innerHTML = `<section class="card consent"><p class="eyebrow">PERMISSION REQUEST</p><h1>Allow this connection?</h1><p><strong>${escape(client.data.client_name ?? clientId)}</strong> wants to act on your behalf.</p><div class="resource"><span class="eyebrow">ONLY FOR THIS RESOURCE</span>${resources.map((r) => `<code>${escape(r)}</code>`).join("")}</div><h3>Requested access</h3><ul class="scopes">${scopes.map((scope) => `<li><span>✓</span><code>${escape(scope)}</code></li>`).join("")}</ul>${query.has("claims") ? `<h3>Additional identity claims</h3><pre>${escape(query.get("claims")!)}</pre>` : ""}<p class="help">Access tokens expire after five minutes. Offline access allows this Client to renew access until its authorization is revoked.</p><p id="message" role="alert"></p><form id="consent"><div class="actions"><button type="submit" name="decision" value="deny" class="secondary">Deny</button><button type="submit" name="decision" value="allow">Allow access →</button></div></form></section>`;
  const form = document.querySelector<HTMLFormElement>("#consent")!;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const accept = (event.submitter as HTMLButtonElement).value === "allow";
    void submit(async () => {
      const result = await auth.oauth2.consent({ accept });
      if (result.error)
        throw new Error("Authorization could not be completed. Restart from your application.");
      if (result.data?.redirect && result.data.url) location.assign(result.data.url);
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

// Keep one-time credentials in this page's memory until the owner acknowledges them.
// A later rotation replaces the now-invalid secret for the same Client.
const pendingCredentials = new Map<string, typeof ClientCredentials.Type>();
function renderCredentials() {
  const box = document.querySelector<HTMLElement>("#credentials")!;
  box.classList.toggle("hidden", pendingCredentials.size === 0);
  box.replaceChildren();
  if (!pendingCredentials.size) return;
  box.innerHTML = `<h2>Save these credentials now</h2><p>Store the Client IDs and, if present, their secrets securely. A client secret is shown only once.</p><button class="secondary">Saved — return to clients</button>`;
  const button = box.querySelector("button")!;
  for (const value of pendingCredentials.values()) {
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(value, null, 2);
    button.before(pre);
  }
  button.addEventListener("click", () => {
    pendingCredentials.clear();
    renderCredentials();
  });
}
function credentials(value: typeof ClientCredentials.Type) {
  pendingCredentials.set(value.client_id, value);
  renderCredentials();
  document.querySelector("#credentials")!.scrollIntoView({ behavior: "smooth" });
}

// The write has already succeeded. A failed read must never invite replaying it.
async function refreshDashboard() {
  try {
    await dashboard();
  } catch {
    // Access-removal confirmations must not use the old listing after a write.
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

async function dashboard() {
  const data = await request(api.clients.list());
  const allowed = (clientId: string) =>
    data.clientAccess
      .filter((access) => access.client_id === clientId)
      .map((access) => access.resource);
  const choices = (selected: readonly string[]) =>
    data.resources
      .map(
        (resource) =>
          `<label class="checkbox resource-choice"><input type="checkbox" name="resources" value="${escape(resource.identifier)}" ${selected.includes(resource.identifier) ? "checked" : ""}><span>${escape(resource.name)}<code>${escape(resource.identifier)}</code><span class="muted">${escape(resource.scopes.join(" · "))}</span></span></label>`,
      )
      .join("");
  const scopeHelp =
    "Separate custom scopes with spaces. Standard identity scopes (openid, profile, email, offline_access) are managed separately.";
  main.className = "dashboard";
  main.innerHTML = `
    <div class="page-title"><div><p class="eyebrow">CONTROL PLANE</p><h1>Clients and Resources</h1><p class="muted">Signed in as ${escape(data.email)}</p></div><button id="logout" class="secondary">Sign out</button></div>
    <div class="issuer"><span class="dot"></span><span>Canonical issuer</span><code>${escape(data.issuer)}</code></div>
    <p id="message" role="alert" tabindex="-1"></p>
    <section id="credentials" class="card hidden" aria-live="polite"></section>
    <fieldset id="dashboard-mutations" aria-label="Clients and Resources">
    <div class="columns dashboard-section"><section><h2>Resources <span class="count">${data.resources.length}</span></h2><p class="muted">Protected APIs and MCP servers, and their available scopes.</p>
    ${
      data.resources.length
        ? data.resources
            .map((resource) => {
              const dependencies = data.clients.filter((client) =>
                allowed(client.client_id).includes(resource.identifier),
              );
              return `<article class="resource"><h3>${escape(resource.name)}</h3><code>${escape(resource.identifier)}</code><span class="muted">${escape(resource.scopes.join(" · "))}</span>
      <p class="help dependencies">Clients with access: ${dependencies.length ? dependencies.map((client) => escape(client.client_name ?? client.client_id)).join(", ") : "None"}</p>
      <details><summary>Edit resource</summary><form data-resource-edit="${escape(resource.identifier)}"><label>Name<input name="name" value="${escape(resource.name)}" required maxlength="100"></label><label>Scopes<input name="scopes" required value="${escape(resource.scopes.join(" "))}"></label><p class="help">${scopeHelp} Clients with access follow these scopes. Added scopes require approval; removing scopes revokes affected renewal credentials. Issued access tokens may remain valid for up to five minutes.</p><button>Save resource</button></form></details>
      <button class="danger" data-resource-delete="${escape(resource.identifier)}" ${dependencies.length ? "disabled" : ""}>Delete resource</button>${dependencies.length ? '<p class="help dependencies">Remove Client access using Manage access below before deleting this Resource.</p>' : ""}</article>`;
            })
            .join("")
        : '<div class="empty"><h3>Add your first Resource</h3><p>Define a protected API or MCP server, then register a Client that can access it.</p></div>'
    }
    </section><section class="card registration"><h2>Add resource</h2><form id="resource-create"><label>Name<input name="name" required maxlength="100" placeholder="OKF MCP"></label><label>HTTPS identifier<input name="identifier" type="url" required placeholder="https://okf.internal/mcp"></label><p class="help">The identifier is the token audience and cannot be edited later.</p><label>Scopes<input name="scopes" required placeholder="okf:read okf:write"></label><p class="help">${scopeHelp}</p><button>Add resource +</button></form></section></div>
    <div class="columns dashboard-section"><section><h2>Clients <span class="count">${data.clients.length}</span></h2><p class="muted">Registered software identities with explicit access to Resources.</p><div class="clients">
    ${
      data.clients.length
        ? data.clients
            .map(
              (
                client,
              ) => `<article class="card client"><div class="client-heading"><h3>${escape(client.client_name ?? "Unnamed client")}</h3><span class="tag">${client.token_endpoint_auth_method === "none" ? "PUBLIC · PKCE" : "CONFIDENTIAL · PKCE"}</span></div><label>Client ID<code>${escape(client.client_id)}</code></label><label>Redirect URI<code>${escape(client.redirect_uris.join(", "))}</code></label>
    <h3>Allowed Resources</h3>${
      data.resources
        .filter((resource) => allowed(client.client_id).includes(resource.identifier))
        .map(
          (resource) =>
            `<div class="allowed-resource"><strong>${escape(resource.name)}</strong><code>${escape(resource.identifier)}</code><span class="muted">${escape(resource.scopes.join(" · "))}</span></div>`,
        )
        .join("") || '<p class="help">No Resource access configured.</p>'
    }
    <details><summary>Manage access</summary><form data-client-access="${escape(client.client_id)}"><fieldset><legend>Allowed Resources</legend>${choices(allowed(client.client_id)) || '<p class="help">Add a Resource above to configure access.</p>'}</fieldset><p class="help">Allows requesting all current and future scopes on selected Resources. Consent is required separately for each Resource. Removing access revokes consent and renewal credentials; issued access tokens may remain valid for up to five minutes.</p><button>Save access</button></form></details>
    <div class="actions">${client.token_endpoint_auth_method !== "none" ? `<button class="secondary" data-rotate="${escape(client.client_id)}">Rotate secret</button>` : ""}<button class="danger" data-delete="${escape(client.client_id)}">Delete client</button></div></article>`,
            )
            .join("")
        : '<div class="empty"><h3>No Clients registered</h3><p>Register a Client with an exact redirect URI and one or more Resources.</p></div>'
    }
    </div></section><section class="card registration"><p class="eyebrow">EXPLICIT REGISTRATION</p><h2>Register client</h2>${data.resources.length ? "" : '<p class="help">Add your first Resource before registering a Client.</p>'}<form id="register"><fieldset ${data.resources.length ? "" : "disabled"}><label>Client name<input name="name" required maxlength="100" placeholder="My MCP client"></label><label>Exact redirect URI<input name="redirect" type="url" required placeholder="https://app.internal/callback"></label><fieldset><legend>Allowed Resources (select at least one)</legend>${choices([])}</fieldset><label class="checkbox"><input type="checkbox" name="native">Native / desktop client (loopback redirect)</label><label class="checkbox"><input type="checkbox" name="confidential">Confidential client (can securely store a secret)</label><button>Register client +</button></fieldset><p class="help">S256 PKCE and consent are required. Dynamic registration is disabled. Client access follows each Resource’s current and future scopes.</p></form></section></div></fieldset>`;
  renderCredentials();
  document.querySelector("#logout")!.addEventListener("click", () => {
    void submit(async () => {
      await auth.signOut();
      location.assign("/login");
    });
  });
  const form = document.querySelector<HTMLFormElement>("#register")!;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submit(async () => {
      const fields = new FormData(form);
      const resources = selectedResources(form);
      if (!resources.length) throw new Error("Select at least one Resource.");
      const result = await request(
        api.clients.create({
          payload: {
            name: textField(fields, "name"),
            redirect: textField(fields, "redirect"),
            resources,
            native: fields.has("native"),
            confidential: fields.has("confidential"),
          },
        }),
      );
      form.reset();
      credentials(result);
      await refreshDashboard();
    });
  });
  const resourceForm = document.querySelector<HTMLFormElement>("#resource-create")!;
  resourceForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void submit(async () => {
      const fields = new FormData(resourceForm);
      await request(
        api.resources.create({
          payload: { identifier: textField(fields, "identifier"), ...resourceFields(fields) },
        }),
      );
      resourceForm.reset();
      await refreshDashboard();
    });
  });
  for (const edit of main.querySelectorAll<HTMLFormElement>("[data-resource-edit]")) {
    edit.addEventListener("submit", (event) => {
      event.preventDefault();
      void submit(async () => {
        await request(
          api.resources.update({
            payload: {
              identifier: edit.dataset.resourceEdit!,
              ...resourceFields(new FormData(edit)),
            },
          }),
        );
        await refreshDashboard();
      });
    });
  }
  for (const edit of main.querySelectorAll<HTMLFormElement>("[data-client-access]")) {
    edit.addEventListener("submit", (event) => {
      event.preventDefault();
      if (submitting) return;
      const client_id = edit.dataset.clientAccess!;
      const resources = selectedResources(edit);
      const removed = allowed(client_id).filter((resource) => !resources.includes(resource));
      if (
        removed.length &&
        !confirm(
          `Remove access to ${removed.join(", ")}? Consent and renewal credentials will be revoked. Issued access tokens may remain valid for up to five minutes. Re-adding access requires fresh authorization.`,
        )
      )
        return;
      void submit(async () => {
        await request(api.clients.access({ payload: { client_id, resources } }));
        await refreshDashboard();
      });
    });
  }
  for (const button of main.querySelectorAll<HTMLButtonElement>(
    "[data-resource-delete], [data-delete], [data-rotate]",
  )) {
    button.addEventListener("click", () => {
      if (submitting) return;
      if (
        !confirm(
          button.dataset.resourceDelete
            ? `Delete Resource ${button.dataset.resourceDelete}? Issued access tokens may remain valid for up to five minutes.`
            : button.dataset.delete
              ? "Delete this Client, its access, consent, and renewal credentials? Issued access tokens may remain valid for up to five minutes."
              : "Rotate the secret immediately? The old secret will stop working.",
        )
      )
        return;
      void submit(async () => {
        if (button.dataset.resourceDelete) {
          await request(
            api.resources.delete({ payload: { identifier: button.dataset.resourceDelete } }),
          );
          await refreshDashboard();
        } else if (button.dataset.delete) {
          await request(api.clients.delete({ payload: { client_id: button.dataset.delete } }));
          pendingCredentials.delete(button.dataset.delete);
          renderCredentials();
          await refreshDashboard();
        } else if (button.dataset.rotate) {
          credentials(
            await request(api.clients.rotate({ payload: { client_id: button.dataset.rotate } })),
          );
        }
      });
    });
  }
}

try {
  const state = await request(api.setup.status());
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
