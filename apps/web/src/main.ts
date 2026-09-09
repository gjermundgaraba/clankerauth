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
  document.querySelector<HTMLElement>("#message")!.textContent = text;
}
let submitting = false;
async function submit(task: () => Promise<void>) {
  if (submitting) return;
  submitting = true;
  const buttons = main.querySelectorAll("button");
  buttons.forEach((button) => (button.disabled = true));
  message("");
  try {
    await task();
  } catch (error) {
    message(error instanceof Error ? error.message : "Request failed");
  } finally {
    buttons.forEach((button) => (button.disabled = false));
    submitting = false;
  }
}

function setup() {
  main.innerHTML = `<section class="intro"><p class="eyebrow">YOUR NETWORK, YOUR IDENTITY</p><h1>Your identity.<br>Starts here.</h1><p>Create the owner account for your private applications.<br>Your account stays on your infrastructure.</p><div class="note"><span class="dot"></span> One owner · Explicit access</div></section><section class="card login"><p class="eyebrow">FIRST-TIME SETUP</p><h2>Create your account</h2><p class="muted">This account manages applications and approves access.</p><form id="setup"><label>Email<input name="email" type="email" autocomplete="username" required placeholder="owner@example.internal"></label><label>Password<input name="password" type="password" autocomplete="new-password" required minlength="8" maxlength="128" aria-describedby="password-help"></label><p id="password-help" class="help">Use 8–128 characters. Save your password somewhere safe.</p><label>Confirm password<input name="confirmation" type="password" autocomplete="new-password" required minlength="8" maxlength="128"></label><p id="message" role="alert"></p><button>Create account <span>→</span></button></form></section>`;
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
            Effect.matchEffect({
              onFailure: (error) =>
                error._tag === "Conflict"
                  ? Effect.sync(() => location.replace("/login"))
                  : Effect.fail(error),
              onSuccess: () => Effect.sync(() => location.replace("/login?setup=complete")),
            }),
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
  main.innerHTML = `<section class="card consent"><p class="eyebrow">PERMISSION REQUEST</p><h1>Allow this connection?</h1><p><strong>${escape(client.data.client_name ?? clientId)}</strong> wants to act on your behalf.</p><div class="resource"><span class="eyebrow">ONLY FOR THIS RESOURCE</span>${resources.map((r) => `<code>${escape(r)}</code>`).join("")}</div><h3>Requested access</h3><ul class="scopes">${scopes.map((scope) => `<li><span>✓</span><code>${escape(scope)}</code></li>`).join("")}</ul>${query.has("claims") ? `<h3>Additional identity claims</h3><pre>${escape(query.get("claims")!)}</pre>` : ""}<p class="help">Access tokens expire after five minutes. Offline access allows this app to renew access until its grant is revoked.</p><p id="message" role="alert"></p><form id="consent"><div class="actions"><button type="submit" name="decision" value="deny" class="secondary">Deny</button><button type="submit" name="decision" value="allow">Allow access →</button></div></form></section>`;
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

async function dashboard() {
  const data = await request(api.clients.list());
  main.className = "dashboard";
  main.innerHTML = `<div class="page-title"><div><p class="eyebrow">CONTROL PLANE</p><h1>Connected applications</h1><p class="muted">Signed in as ${escape(data.email)}</p></div><button id="logout" class="secondary">Sign out</button></div><div class="issuer"><span class="dot"></span><span>Canonical issuer</span><code>${escape(data.issuer)}</code></div><div class="columns"><section><h2>Registered clients <span class="count">${data.clients.length}</span></h2><p class="muted">Only explicitly registered applications can request access.</p><div class="clients">${data.clients.length ? data.clients.map((client) => `<article class="card client"><div class="client-heading"><h3>${escape(client.client_name ?? "Unnamed client")}</h3><span class="tag">${client.token_endpoint_auth_method === "none" ? "PUBLIC · PKCE" : "CONFIDENTIAL · PKCE"}</span></div><label>Client ID<code>${escape(client.client_id)}</code></label><label>Redirect URI<code>${escape(client.redirect_uris.join(", "))}</code></label><div class="actions">${client.token_endpoint_auth_method !== "none" ? `<button class="secondary" data-rotate="${escape(client.client_id)}">Rotate secret</button>` : ""}<button class="danger" data-delete="${escape(client.client_id)}">Delete client</button></div></article>`).join("") : `<div class="empty"><h3>No clients registered</h3><p>Add your first app with an exact redirect URI and one resource.</p></div>`}</div><h2>Resource policy</h2>${data.resources.map((r) => `<div class="resource"><strong>${escape(r.name)}</strong><code>${escape(r.identifier)}</code><span class="muted">${escape(r.scopes.join(" · "))}</span></div>`).join("")}</section><section class="card registration"><p class="eyebrow">EXPLICIT REGISTRATION</p><h2>Add an application</h2><form id="register"><label>Application name<input name="name" required maxlength="100" placeholder="My MCP client"></label><label>Exact redirect URI<input name="redirect" type="url" required placeholder="https://app.internal/callback"></label><label>Allowed resource<select name="resource">${data.resources.map((r) => `<option value="${escape(r.identifier)}">${escape(r.name)}</option>`).join("")}</select></label><label class="checkbox"><input type="checkbox" name="native">Native / desktop client (loopback redirect)</label><label class="checkbox"><input type="checkbox" name="confidential">Confidential client (can securely store a secret)</label><button>Register application +</button><p class="help">S256 PKCE and consent are required. Dynamic registration is disabled.</p></form></section></div><p id="message" role="alert"></p><section id="credentials" class="card hidden" aria-live="polite"></section>`;
  document.querySelector("#logout")!.addEventListener("click", () => {
    void submit(async () => {
      await auth.signOut();
      location.assign("/login");
    });
  });
  const form = document.querySelector<HTMLFormElement>("#register")!;
  function credentials(value: typeof ClientCredentials.Type) {
    const box = document.querySelector<HTMLElement>("#credentials")!;
    box.classList.remove("hidden");
    box.innerHTML = `<h2>Save these credentials now</h2><p>The client secret is shown only once. Store it in your application's secret manager.</p><pre></pre><button class="secondary" id="done">Saved — return to clients</button>`;
    box.querySelector("pre")!.textContent = JSON.stringify(value, null, 2);
    box.querySelector("button")!.addEventListener("click", () => location.reload());
    box.scrollIntoView({ behavior: "smooth" });
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submit(async () => {
      const fields = new FormData(form);
      const textField = (name: string) => {
        const value = fields.get(name);
        if (typeof value !== "string") throw new Error(`Missing form field: ${name}`);
        return value;
      };
      credentials(
        await request(
          api.clients.create({
            payload: {
              name: textField("name"),
              redirect: textField("redirect"),
              resource: textField("resource"),
              native: fields.has("native"),
              confidential: fields.has("confidential"),
            },
          }),
        ),
      );
      form.reset();
    });
  });
  for (const button of document.querySelectorAll<HTMLButtonElement>(
    "[data-delete], [data-rotate]",
  )) {
    button.addEventListener("click", () => {
      if (submitting) return;
      if (
        !confirm(
          button.dataset.delete
            ? "Delete this client and its stored grants? Existing JWTs can remain valid for up to five minutes."
            : "Rotate the secret immediately? The old secret will stop working.",
        )
      )
        return;
      void submit(async () => {
        if (button.dataset.delete) {
          await request(api.clients.delete({ payload: { client_id: button.dataset.delete } }));
          location.reload();
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
