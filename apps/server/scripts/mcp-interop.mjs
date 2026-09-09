import { Effect } from "effect";
// Optional integration test. See docs/mcp-interop.md. Never uses live Code Storage.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import {
  requestToResourceInput,
  verifyAccessTokenRequest,
  isInsufficientScopeError,
} from "better-auth/oauth2";
import { application } from "../src/app.ts";
import { openAuth, initialize } from "../src/auth.ts";

const root = resolve(process.argv[2] ?? "missing-okf-checkout");
const external = createRequire(join(root, "package.json"));
const {
  Client,
  StreamableHTTPClientTransport,
  auth: sdkAuth,
  UnauthorizedError,
} = await import(pathToFileURL(external.resolve("@modelcontextprotocol/client")));
const { startHttpServer } = await import(pathToFileURL(join(root, "packages/cli/src/http.ts")));
const { Actor } = await import(pathToFileURL(join(root, "packages/kernel/dist/index.mjs")));
const { makeCodeStorageStoreWithClient } = await import(
  pathToFileURL(join(root, "packages/repo/dist/index.mjs"))
);
const { makeFakeClient } = await import(
  pathToFileURL(join(root, "packages/repo/tests/support/fake-client.ts"))
);
const directory = await mkdtemp(join(tmpdir(), "clankerauth-mcp-"));
const servers = [];
const clients = [];
let service;
let app;
let upstream;
let forwarded = 0;
let storageCalls = 0;
let jwksReads = 0;
let tokenRequests = 0;
const discoveryReads = [];
const resource = "https://mcp.interop.invalid/mcp";
const otherResource = "https://other.interop.invalid/api";
const metadataURL = "https://mcp.interop.invalid/.well-known/oauth-protected-resource/mcp";
const password = randomBytes(24).toString("base64url");
const email = "interop@example.internal";
let cookie = "";

async function listen(handler) {
  const server = createServer(async (incoming, outgoing) => {
    try {
      const chunks = [];
      for await (const chunk of incoming) chunks.push(chunk);
      const headers = new Headers();
      for (const [key, value] of Object.entries(incoming.headers))
        if (value) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
      const response = await handler(incoming, headers, Buffer.concat(chunks));
      outgoing.writeHead(response.status, {
        ...Object.fromEntries(response.headers),
        "set-cookie": response.headers.getSetCookie(),
      });
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      console.error("Harness handler failure:", error.message);
      outgoing.writeHead(500).end();
    }
  });
  servers.push(server);
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  return `http://127.0.0.1:${server.address().port}`;
}
function requestAt(url, incoming, headers, body) {
  return new Request(url, {
    method: incoming.method,
    headers,
    body: ["GET", "HEAD"].includes(incoming.method) ? undefined : body,
  });
}
let issuer;
async function ownerRequest(path, body) {
  const response = await fetch(new URL(path, service.settings.baseURL), {
    method: body ? "POST" : "GET",
    redirect: "manual",
    headers: {
      origin: service.settings.baseURL,
      cookie,
      ...(body ? { "content-type": "application/json" } : { accept: "text/html" }),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const fresh = response.headers.getSetCookie();
  if (fresh.length) cookie = fresh.map((c) => c.split(";")[0]).join("; ");
  return response;
}
async function register(target) {
  const response = await ownerRequest("/admin/clients", {
    name: "Official SDK interoperability",
    redirect: "http://127.0.0.1:9876/callback",
    resources: [target],
    native: true,
    confidential: false,
  });
  assert.equal(response.status, 201, await response.clone().text());
  return response.json();
}

try {
  let handler;
  const authURL = await listen((incoming, headers, body) => {
    if (incoming.url.startsWith("/api/auth/jwks")) jwksReads++;
    if (incoming.url === "/api/auth/oauth2/token") tokenRequests++;
    if (incoming.url.includes(".well-known")) discoveryReads.push(incoming.url);
    return handler(requestAt(`${authURL}${incoming.url}`, incoming, headers, body));
  });
  const settings = {
    baseURL: authURL,
    secret: randomBytes(32).toString("hex"),
    database: join(directory, "auth.sqlite"),
    host: "127.0.0.1",
    port: Number(new URL(authURL).port),
  };
  service = await openAuth(settings);
  await initialize(service);
  app = application(service);
  handler = app;
  const setup = await ownerRequest("/api/setup", { email, password });
  assert.equal(setup.status, 201, await setup.clone().text());
  assert.equal(setup.headers.has("set-cookie"), false);
  issuer = `${authURL}/api/auth`;
  const login = await ownerRequest("/api/auth/sign-in/email", { email, password });
  assert.equal(login.status, 200);
  for (const input of [
    { identifier: resource, name: "MCP", scopes: ["okf:read", "okf:write"] },
    { identifier: otherResource, name: "Other", scopes: ["okf:read", "okf:write"] },
  ]) {
    const created = await ownerRequest("/admin/resources", input);
    assert.equal(created.status, 201, await created.clone().text());
  }
  const registered = await register(resource);
  const otherClient = await register(otherResource);
  const backing = makeCodeStorageStoreWithClient(makeFakeClient(join(directory, "fake-storage")));
  const store = Object.fromEntries(
    Object.entries(backing).map(([name, method]) => [
      name,
      (...args) => {
        storageCalls++;
        return method(...args);
      },
    ]),
  );
  upstream = await startHttpServer({
    store,
    actor: Actor.make("human:interop-owner"),
    port: 0,
    bindHost: "127.0.0.1",
    publicUrl: new URL("https://127.0.0.1"),
  });
  const proxyURL = await listen(async (incoming, headers, body) => {
    if (incoming.url === "/.well-known/oauth-protected-resource/mcp") {
      discoveryReads.push(incoming.url);
      return Response.json({
        resource,
        authorization_servers: [issuer],
        scopes_supported: ["okf:read", "okf:write"],
        bearer_methods_supported: ["header"],
      });
    }
    if (incoming.url !== "/mcp") return new Response(null, { status: 404 });
    const message = body.length ? JSON.parse(body.toString()) : {};
    const write =
      message.method === "tools/call" &&
      ["create_bundle", "delete_bundle", "change"].includes(message.params?.name);
    const scope = write ? "okf:write" : "okf:read";
    try {
      const claims = await verifyAccessTokenRequest(
        requestToResourceInput(requestAt(resource, incoming, headers, body)),
        {
          jwksUrl: `${issuer}/jwks`,
          verifyOptions: { issuer, audience: resource, algorithms: ["EdDSA"], typ: "at+jwt" },
          requiredScopes: [scope],
        },
      );
      assert.equal(
        claims.sub,
        await Effect.runPromise(service.owner()),
        "Only the test owner is authorized by this prototype policy",
      );
    } catch (error) {
      const insufficient = isInsufficientScopeError(error);
      return new Response(null, {
        status: insufficient ? 403 : 401,
        headers: {
          "www-authenticate": `Bearer resource_metadata="${metadataURL}", scope="${insufficient ? scope : "okf:read okf:write"}"${insufficient ? ', error="insufficient_scope"' : ""}`,
        },
      });
    }
    forwarded++;
    headers.set("host", "127.0.0.1");
    headers.delete("authorization");
    headers.delete("origin");
    return fetch(`http://127.0.0.1:${upstream.port}/mcp`, {
      method: incoming.method,
      headers,
      body: ["GET", "HEAD"].includes(incoming.method) ? undefined : body,
    });
  });
  // Test-only DNS/TLS substitute: only the reserved resource origin maps to the local HTTP proxy.
  // All SDK discovery, token exchange, JWKS and MCP messages still traverse actual HTTP listeners.
  const routedFetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input);
    if (url.origin === "https://mcp.interop.invalid")
      return fetch(`${proxyURL}${url.pathname}${url.search}`, init);
    return fetch(input, init);
  };
  function providerFor(client) {
    let savedTokens, verifier, discovery, authorization;
    return {
      redirectUrl: "http://127.0.0.1:9876/callback",
      clientMetadata: {
        redirect_uris: ["http://127.0.0.1:9876/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        application_type: "native",
        scope: "okf:read okf:write offline_access",
      },
      state: () => "interop-state",
      // This fixture registers public clients. Provider responses may include
      // null secret fields; the SDK interprets any defined secret as confidential.
      clientInformation: () => ({
        client_id: client.client_id,
        token_endpoint_auth_method: "none",
        issuer,
      }),
      tokens: () => savedTokens,
      saveTokens: (value) => {
        savedTokens = value;
      },
      saveCodeVerifier: (value) => {
        verifier = value;
      },
      codeVerifier: () => verifier,
      redirectToAuthorization: (value) => {
        authorization = value;
      },
      saveDiscoveryState: (value) => {
        discovery = value;
      },
      discoveryState: () => discovery,
      authorization: () => authorization,
    };
  }
  async function redirectLocation(response) {
    if (response.status === 302) return new URL(response.headers.get("location"), authURL);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.redirect, true);
    return new URL(body.url, authURL);
  }
  async function consent(provider, requireLogin = false) {
    const authorization = provider.authorization();
    assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
    assert.equal(authorization.searchParams.get("resource"), resource);
    if (requireLogin) cookie = "";
    const response = await ownerRequest(authorization);
    let location = await redirectLocation(response);
    if (requireLogin) {
      assert.equal(location.pathname, "/login");
      const signedIn = await ownerRequest("/api/auth/sign-in/email", {
        email,
        password,
        oauth_query: location.search.slice(1),
      });
      assert.equal(signedIn.status, 200);
      location = new URL((await signedIn.json()).url, authURL);
    }
    assert.equal(location.pathname, "/consent");
    const accepted = await ownerRequest("/api/auth/oauth2/consent", {
      accept: true,
      oauth_query: location.search.slice(1),
    });
    assert.equal(accepted.status, 200);
    const callback = new URL((await accepted.json()).url);
    assert.equal(callback.searchParams.get("state"), "interop-state");
    assert.equal(callback.searchParams.get("iss"), issuer);
    return callback.searchParams;
  }
  const call = (token) =>
    routedFetch(resource, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "create_bundle", arguments: { repo: "blocked", bundle: "blocked" } },
      }),
    });
  for (const token of [undefined, "not-a-token"]) {
    const response = await call(token);
    assert.equal(response.status, 401);
    assert.ok(response.headers.get("www-authenticate").includes(metadataURL));
  }
  assert.equal(forwarded, 0);
  assert.equal(storageCalls, 0);
  console.log("PASS missing/invalid tokens: HTTP 401; forwarded=0; storageCalls=0");

  const provider = providerFor(registered);
  const transport = new StreamableHTTPClientTransport(new URL(resource), {
    authProvider: provider,
    fetch: routedFetch,
  });
  const sdk = new Client(
    { name: "clankerauth-interop", version: "1.0.0" },
    { versionNegotiation: { mode: "auto" } },
  );
  clients.push(sdk);
  await assert.rejects(sdk.connect(transport), (error) => error instanceof UnauthorizedError);
  assert.ok(provider.authorization(), "SDK should initiate authorization after resource challenge");
  assert.ok(discoveryReads.includes("/.well-known/oauth-protected-resource/mcp"));
  assert.ok(discoveryReads.some((path) => path.includes("oauth-authorization-server")));
  const callbackParams = await consent(provider, true);
  const mismatchedIssuer = new URLSearchParams(callbackParams);
  mismatchedIssuer.set("iss", "https://untrusted.interop.invalid");
  await assert.rejects(transport.finishAuth(mismatchedIssuer), /issuer/i);
  assert.equal(
    tokenRequests,
    0,
    "SDK must reject wrong callback issuer before exchanging the code",
  );
  await transport.finishAuth(callbackParams);
  assert.equal(provider.tokens().issuer, issuer);
  assert.ok(provider.tokens().refresh_token);
  console.log(
    "PASS official SDK challenge -> resource metadata -> issuer discovery -> owner login/consent -> S256 exchange",
  );
  const connected = new Client(
    { name: "clankerauth-interop", version: "1.0.0" },
    { versionNegotiation: { mode: "auto" } },
  );
  clients.push(connected);
  await connected.connect(
    new StreamableHTTPClientTransport(new URL(resource), {
      authProvider: provider,
      fetch: routedFetch,
    }),
  );
  const tools = await connected.listTools();
  assert.ok(tools.tools.some((t) => t.name === "create_bundle"));
  const created = await connected.callTool({
    name: "create_bundle",
    arguments: { repo: "interop", bundle: "proof" },
  });
  assert.ok(!created.isError, JSON.stringify(created));
  assert.ok(created.structuredContent.revision);
  const repos = await connected.callTool({ name: "list_repos", arguments: {} });
  assert.deepEqual(repos.structuredContent, { repos: ["interop"] });
  assert.ok(storageCalls > 0);
  assert.ok(jwksReads > 0);
  console.log(
    `PASS real clanker-okf tools/list (${tools.tools.length} tools), create_bundle and list_repos => {repos:["interop"]}; JWKS fetched`,
  );

  // Obtain a real signed token for a different resource through the same official SDK.
  const otherProvider = providerFor(otherClient);
  const otherFetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input);
    if (url.origin === "https://other.interop.invalid" && url.pathname.includes(".well-known"))
      return Promise.resolve(
        Response.json({
          resource: otherResource,
          authorization_servers: [issuer],
          scopes_supported: ["okf:read", "okf:write"],
        }),
      );
    return routedFetch(input, init);
  };
  assert.equal(
    await sdkAuth(otherProvider, {
      serverUrl: otherResource,
      scope: "okf:read okf:write",
      fetchFn: otherFetch,
    }),
    "REDIRECT",
  );
  const otherAuthorization = otherProvider.authorization();
  assert.equal(otherAuthorization.searchParams.get("resource"), otherResource);
  const otherResponse = await ownerRequest(otherAuthorization);
  const otherLocation = await redirectLocation(otherResponse);
  const otherConsent = await ownerRequest("/api/auth/oauth2/consent", {
    accept: true,
    oauth_query: otherLocation.search.slice(1),
  });
  const otherCallback = new URL((await otherConsent.json()).url);
  assert.equal(
    await sdkAuth(otherProvider, {
      serverUrl: otherResource,
      authorizationCode: otherCallback.searchParams.get("code"),
      iss: otherCallback.searchParams.get("iss"),
      fetchFn: otherFetch,
    }),
    "AUTHORIZED",
  );
  await verifyAccessTokenRequest(
    requestToResourceInput(
      new Request(otherResource, {
        headers: { authorization: `Bearer ${otherProvider.tokens().access_token}` },
      }),
    ),
    {
      jwksUrl: `${issuer}/jwks`,
      verifyOptions: { issuer, audience: otherResource, algorithms: ["EdDSA"], typ: "at+jwt" },
      requiredScopes: ["okf:write"],
    },
  );
  const before = { forwarded, storageCalls };
  assert.equal((await call(otherProvider.tokens().access_token)).status, 401);
  const tampered = provider.tokens().access_token.split(".");
  tampered[1] = Buffer.from(
    JSON.stringify({ ...JSON.parse(Buffer.from(tampered[1], "base64url")), scope: "okf:write" }),
  ).toString("base64url");
  assert.equal((await call(tampered.join("."))).status, 401);
  assert.deepEqual({ forwarded, storageCalls }, before);
  console.log(
    "PASS validly signed wrong-audience token and tampered JWT: HTTP 401; zero additional forwarding/storage execution",
  );
  const readClient = await register(resource);
  const readProvider = providerFor(readClient);
  assert.equal(
    await sdkAuth(readProvider, { serverUrl: resource, scope: "okf:read", fetchFn: routedFetch }),
    "REDIRECT",
  );
  const readCallback = await consent(readProvider);
  assert.equal(
    await sdkAuth(readProvider, {
      serverUrl: resource,
      authorizationCode: readCallback.get("code"),
      iss: readCallback.get("iss"),
      fetchFn: routedFetch,
    }),
    "AUTHORIZED",
  );
  const deniedWrite = await call(readProvider.tokens().access_token);
  assert.equal(deniedWrite.status, 403);
  assert.ok(deniedWrite.headers.get("www-authenticate").includes('error="insufficient_scope"'));
  assert.deepEqual({ forwarded, storageCalls }, before);
  console.log(
    "PASS read-only token cannot execute create_bundle: HTTP 403 insufficient_scope; zero additional forwarding/storage execution",
  );
  const refreshBefore = provider.tokens().refresh_token;
  assert.equal(
    await sdkAuth(provider, { serverUrl: resource, fetchFn: routedFetch }),
    "AUTHORIZED",
  );
  assert.notEqual(provider.tokens().refresh_token, refreshBefore);
  assert.deepEqual(
    (await connected.callTool({ name: "list_repos", arguments: {} })).structuredContent,
    { repos: ["interop"] },
  );
  console.log("PASS official SDK refresh rotation followed by authenticated real MCP action");
  console.log(
    "PROTOTYPE INTEGRATION PASSED; no shipped clanker-okf auth, real storage credentials, or preview state used",
  );
} finally {
  const cleanupErrors = [];
  const attempt = async (operation) => {
    try {
      await operation();
    } catch (error) {
      cleanupErrors.push(error);
    }
  };
  for (const client of clients) await attempt(() => client.close());
  await attempt(() => upstream?.close());
  for (const server of servers.reverse()) {
    await attempt(() => server.closeAllConnections());
    await attempt(
      () =>
        new Promise((done, reject) =>
          server.close((error) => {
            if (error && error.code !== "ERR_SERVER_NOT_RUNNING") reject(error);
            else done();
          }),
        ),
    );
  }
  await attempt(() => app?.dispose());
  await attempt(() => service?.close());
  await attempt(() => rm(directory, { recursive: true, force: true }));
  if (cleanupErrors.length) {
    console.error(new AggregateError(cleanupErrors, "Interop harness cleanup failed"));
    process.exitCode = 1;
  }
}
