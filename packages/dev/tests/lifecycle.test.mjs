import assert from "node:assert/strict";
import { access, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createServer, request } from "node:http";
import { once } from "node:events";
import { startDisposableIssuer } from "../dist/index.mjs";
import { attach, reserveLoopbackPort } from "../dist/edge.mjs";

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

await test("a cookie domain serves forward auth: the signed-in owner gets a resource token", async () => {
  const app = "http://app.notes.localhost:9876";
  const forwarded = { identifier: `${app}/api`, name: "Notes API", scopes: ["notes:read"] };

  const forward = (issuer, cookie) =>
    fetch(`${issuer.url}/forward-auth?resource=${encodeURIComponent(forwarded.identifier)}`, {
      redirect: "manual",
      headers: {
        cookie,
        "x-forwarded-proto": "http",
        "x-forwarded-host": "app.notes.localhost:9876",
        "x-forwarded-uri": "/docs",
      },
    });

  const issuer = await startDisposableIssuer({
    resources: [forwarded],
    client: { ...options.client, resources: [forwarded.identifier] },
    cookieDomain: "notes.localhost",
  });

  try {
    assert.equal(new URL(issuer.url).hostname, "auth.notes.localhost");
    assert.equal(issuer.issuer, `${issuer.url}/api/auth`);
    // Node's fetch is a script's request, not a navigation, so no session is refused in place.
    const anonymous = await forward(issuer, "");
    assert.equal(anonymous.status, 401);
    await anonymous.body.cancel();
    const session = await login(issuer);
    assert.equal(session.status, 200);

    const cookie = session.headers
      .getSetCookie()
      .map((part) => part.split(";")[0])
      .join("; ");

    await session.body.cancel();

    const proceed = await fetch(
      `${issuer.url}/forward-auth/continue?rd=${encodeURIComponent(`${app}/docs`)}`,
      { redirect: "manual", headers: { cookie } },
    );

    assert.equal(proceed.status, 302);
    assert.equal(proceed.headers.get("location"), `${app}/docs`);
    const shared = proceed.headers.getSetCookie().find((part) => part.includes("Domain="));
    assert.match(shared, /Domain=notes\.localhost/);
    const decision = await forward(issuer, shared.split(";")[0]);
    assert.equal(decision.status, 204);
    assert.match(decision.headers.get("authorization"), /^Bearer /);
  } finally {
    await issuer.close();
  }
});

await test("without a cookie domain the forward-auth routes are not served", async () => {
  const issuer = await startDisposableIssuer(options);

  try {
    const response = await fetch(`${issuer.url}/forward-auth?resource=x`);
    assert.equal(response.status, 404);
    await response.body.cancel();
  } finally {
    await issuer.close();
  }
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

await test("a data directory keeps the owner, the secret and the client across restarts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "clankerauth-workspace-"));
  const port = await reserveLoopbackPort();
  const workspace = { ...options, dataDir: directory, port };
  const first = await startDisposableIssuer(workspace);

  try {
    assert.equal(first.directory, directory);
    assert.equal(first.port, port);
    assert.equal(new URL(first.url).port, String(port));
    const key = await first.apiKey({ permissions: { [resource.identifier]: ["example:read"] } });
    assert.match(key, /^ca_/);
    await first.close();
    // The directory is the caller's, so closing leaves it alone.
    await access(join(directory, "credentials.json"));

    const second = await startDisposableIssuer(workspace);

    try {
      assert.deepEqual(second.owner, first.owner);
      assert.equal(second.clientId, first.clientId);
      assert.equal(second.clientSecret, first.clientSecret);
      const session = await login(second);
      assert.equal(session.status, 200);
      await session.body.cancel();

      const cookie = session.headers
        .getSetCookie()
        .map((part) => part.split(";")[0])
        .join("; ");

      const state = await (
        await fetch(`${second.url}/api/administration/listClients`, {
          method: "POST",
          headers: { cookie, origin: second.url, "content-type": "application/json" },
          body: "{}",
        })
      ).json();

      // Provisioning is idempotent: no second copy of the resource or the client.
      assert.equal(state.clients.length, 1);
      assert.equal(state.resources.length, 2);

      // The signing secret survived, so the key minted before the restart still verifies.
      const verified = await fetch(`${second.url}/api/issuer/verifyApiKey`, {
        method: "POST",
        headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
        body: JSON.stringify({ resource: resource.identifier }),
      });

      assert.equal(verified.status, 200);
      assert.deepEqual((await verified.json()).scopes, ["example:read"]);
    } finally {
      await second.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test("owner sessions and tokens are provisioned without a hand-rolled cookie jar", async () => {
  const app = "http://app.notes.localhost:9877";
  const forwarded = { identifier: `${app}/`, name: "Notes", scopes: ["notes:read"] };

  const issuer = await startDisposableIssuer({
    resources: [forwarded],
    client: { ...options.client, resources: [forwarded.identifier] },
    cookieDomain: "notes.localhost",
  });

  try {
    const session = await issuer.ownerSession(app);
    assert.match(session.cookie, /clankerauth_forward=/);
    assert.ok(session.cookies.some((entry) => entry.name === "clankerauth_forward"));

    const token = await issuer.ownerToken({ resource: forwarded.identifier, appOrigin: app });
    const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
    assert.equal(claims.aud, forwarded.identifier);
    assert.equal(claims.client_id, "forward-auth");
    assert.equal(claims.scope, "notes:read");
  } finally {
    await issuer.close();
  }
});

await test("the forward-auth edge checks requests, proxies a socket and survives its errors", async () => {
  const port = await reserveLoopbackPort();
  const app = `http://app.notes.localhost:${port}`;
  const forwarded = { identifier: `${app}/`, name: "Notes", scopes: ["notes:read"] };

  const issuer = await startDisposableIssuer({
    resources: [forwarded],
    client: { ...options.client, resources: [forwarded.identifier] },
    cookieDomain: "notes.localhost",
  });

  const seen = [];
  const errors = [];
  // An upgraded socket is no longer the server's to close, so the test owns every one.
  const sockets = new Set();
  const track = (socket) => sockets.add(socket.once("close", () => sockets.delete(socket)));

  const upgradeHosts = [];

  // The app behind the edge: it answers HTTP and accepts one upgraded socket.
  const backend = createServer((incoming, outgoing) => {
    seen.push(incoming.headers.authorization ?? null);
    outgoing.writeHead(200, { "content-type": "text/plain" }).end("app");
  });

  backend.on("upgrade", (incoming, socket) => {
    track(socket);
    seen.push(incoming.headers.authorization ?? null);
    upgradeHosts.push(incoming.headers.host ?? null);
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    );
    socket.write("hello");
  });

  await new Promise((done) => backend.listen(0, "127.0.0.1", done));
  const backendUrl = `http://127.0.0.1:${backend.address().port}`;

  const edge = createServer();

  const handle = attach(edge, {
    issuer: issuer.url,
    appOrigin: app,
    resource: forwarded.identifier,
    backend: backendUrl,
    socketPaths: ["/sync"],
    onError: (error) => errors.push(error.message),
  });

  edge.on("request", (incoming, outgoing) =>
    handle(incoming, outgoing, () => {
      const upstream = request(
        `${backendUrl}${incoming.url}`,
        { headers: incoming.headers },
        (answer) => {
          outgoing.writeHead(answer.statusCode, answer.headers);
          answer.pipe(outgoing);
        },
      );

      incoming.pipe(upstream);
    }),
  );

  // The edge returns the upgrades it does not own, the way it leaves Vite's HMR socket
  // alone; whoever else listens answers them.
  edge.on("upgrade", (incoming, socket) => {
    const path = incoming.url.split("?")[0];

    if (path === "/sync" || path.startsWith("/sync/")) return;
    track(socket);
    socket.end("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
  });

  await new Promise((done) => edge.listen(port, "127.0.0.1", done));

  // node:http, not fetch: `fetch` owns Sec-Fetch-Mode, and that header is what decides
  // whether the issuer may redirect a request through sign-in.
  const get = (path, headers = {}) =>
    new Promise((resolve, reject) => {
      const attempt = request(`http://127.0.0.1:${port}${path}`, { headers }, (answer) => {
        let body = "";

        answer.setEncoding("utf8");
        answer.on("data", (chunk) => (body += chunk));
        answer.on("end", () =>
          resolve({ status: answer.statusCode, headers: answer.headers, body }),
        );
      });

      attempt.on("error", reject);
      attempt.end();
    });

  try {
    // A script's request without a session is refused in place, never redirected.
    const anonymous = await get("/docs");
    assert.equal(anonymous.status, 401);
    assert.deepEqual(seen, []);

    // Public paths never reach the issuer at all.
    const probe = await get("/healthz");
    assert.equal(probe.status, 200);
    assert.deepEqual(seen, [null]);

    const { cookie } = await issuer.ownerSession(app);
    const admitted = await get("/docs", { cookie });
    assert.equal(admitted.status, 200);
    assert.equal(admitted.body, "app");
    assert.match(seen.at(-1), /^Bearer /);

    // A navigation without a session goes through sign-in instead.
    const navigation = await get("/docs", { "sec-fetch-mode": "navigate" });
    assert.equal(navigation.status, 302);
    assert.match(navigation.headers.location, /\/forward-auth\/continue/);

    const openSocket = (path, headers) =>
      new Promise((resolve, reject) => {
        const attempt = request(`http://127.0.0.1:${port}${path}`, {
          headers: { connection: "Upgrade", upgrade: "websocket", ...headers },
        });

        attempt.on("upgrade", (answer, socket, head) => {
          track(socket);
          resolve({ status: 101, head, socket });
        });
        attempt.on("response", (answer) => {
          answer.resume();
          resolve({ status: answer.statusCode });
        });
        attempt.on("error", reject);
        attempt.end();
      });

    const refused = await openSocket("/sync", {});
    assert.equal(refused.status, 401);

    const proxied = await openSocket("/sync", { cookie });
    assert.equal(proxied.status, 101);

    const greeting = proxied.head.length
      ? proxied.head.toString()
      : await new Promise((resolve) =>
          proxied.socket.once("data", (chunk) => resolve(String(chunk))),
        );

    assert.equal(greeting, "hello");
    assert.match(seen.at(-1), /^Bearer /);
    // The app's request policy answers only for its public host, so the edge must not rewrite it.
    assert.equal(upgradeHosts.at(-1), `127.0.0.1:${port}`);
    proxied.socket.destroy();

    // An upgrade on a path the edge does not own is left to whoever else listens.
    const untouched = await openSocket("/hmr", { cookie });
    assert.equal(untouched.status, 200);

    // An unreachable issuer is a 502 the caller sees, not a crash.
    await issuer.close();
    const broken = await get("/docs", { cookie });
    assert.equal(broken.status, 502);
  } finally {
    for (const socket of sockets) socket.destroy();

    const stopped = Promise.all([
      new Promise((done) => edge.close(done)),
      new Promise((done) => backend.close(done)),
    ]);

    edge.closeAllConnections();
    backend.closeAllConnections();
    await stopped;
    await issuer.close();
  }
});
