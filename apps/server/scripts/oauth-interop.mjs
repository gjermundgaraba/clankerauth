// Exercise the supplied clanker-okf checkout with both DCR and CIMD; see docs/mcp-interop.md.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, request as httpRequest } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(process.argv[2]);
const authRoot = fileURLToPath(new URL("../../..", import.meta.url));
const sdkRoot = resolve(process.argv[3] ?? process.env.MCP_SDK_ROOT ?? "/tmp/okf-oauth-sdk");
const external = createRequire(join(sdkRoot, "package.json"));
const {
  Client,
  StreamableHTTPClientTransport,
  auth: sdkAuth,
  UnauthorizedError,
} = await import(pathToFileURL(external.resolve("@modelcontextprotocol/client")));
const loadAuth = (name) => import(pathToFileURL(join(authRoot, `apps/server/src/${name}.ts`)));
const { application } = await loadAuth("app");
const { openAuth, initialize } = await loadAuth("auth");
const loadOkf = (path) => import(pathToFileURL(join(root, "packages", path)));
const { startHttpServer } = await loadOkf("cli/src/http.ts");
const { createClient, AuthenticationError } = await loadOkf("client/src/index.ts");
const { makeCodeStorageStoreWithClient } = await loadOkf("repo/src/index.ts");
const { makeFakeClient } = await loadOkf("repo/tests/support/fake-client.ts");
const directory = await mkdtemp(join(tmpdir(), "okf-oauth-interop-"));
const origin = "https://mcp.interop.invalid";
const resource = `${origin}/mcp`;
const apiResource = `${origin}/api`;
const password = randomBytes(24).toString("base64url");
const email = "interop@example.internal";
const clients = [];
let service, upstream, authServer, issuer, authURL;
let cookie = "";
let storageCalls = 0;
let jwksReads = 0;
let tokenRequests = 0;
let registrationRequests = 0;
let metadataFetches = 0;
const metadataUrl = "https://client.interop.invalid/oauth/client.json";
const discoveryReads = [];

async function ownerRequest(path, body) {
  const response = await fetch(new URL(path, authURL), {
    method: body ? "POST" : "GET",
    redirect: "manual",
    headers: {
      origin: authURL,
      cookie,
      ...(body ? { "content-type": "application/json" } : { accept: "text/html" }),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const fresh = response.headers.getSetCookie();
  if (fresh.length) cookie = fresh.map((value) => value.split(";")[0]).join("; ");
  return response;
}
async function expectStatus(response, status) {
  assert.equal(response.status, status, `${response.url}: ${await response.clone().text()}`);
}
// DNS/TLS substitute only: no verifier, challenge fixture, or authorization proxy.
async function routedFetch(input, init) {
  const request = new Request(input, init);
  const url = new URL(request.url);
  if (url.origin !== origin) return fetch(request);
  if (url.pathname.includes(".well-known")) discoveryReads.push(url.pathname);
  const headers = new Headers(request.headers);
  headers.set("host", "mcp.interop.invalid");
  const body = ["GET", "HEAD"].includes(request.method)
    ? undefined
    : Buffer.from(await request.arrayBuffer());
  // Node fetch can replace Host; node:http preserves the canonical Host explicitly.
  return new Promise((done, reject) => {
    const outgoing = httpRequest(
      `http://127.0.0.1:${upstream.port}${url.pathname}${url.search}`,
      {
        method: request.method,
        headers: Object.fromEntries(headers),
        signal: request.signal,
      },
      (incoming) => {
        const responseHeaders = new Headers();
        for (const [key, value] of Object.entries(incoming.headers))
          if (value) responseHeaders.set(key, Array.isArray(value) ? value.join(", ") : value);
        const empty = [204, 205, 304].includes(incoming.statusCode) || request.method === "HEAD";
        if (empty) incoming.resume();
        const response = new Response(empty ? null : Readable.toWeb(incoming), {
          status: incoming.statusCode,
          headers: responseHeaders,
        });
        Object.defineProperty(response, "url", { value: request.url });
        done(response);
      },
    );
    outgoing.on("error", reject);
    outgoing.end(body);
  });
}
function providerFor(client, clientMetadataUrl) {
  let tokens, verifier, discovery, authorization;
  let information = client;
  return {
    clientMetadataUrl,
    redirectUrl: "http://127.0.0.1:9876/callback",
    clientMetadata: {
      client_name: "Isolated OKF interoperability",
      redirect_uris: ["http://127.0.0.1:9876/callback"],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      application_type: "native",
      scope: "okf:read okf:write offline_access",
    },
    state: () => "interop-state",
    clientInformation: () => information,
    saveClientInformation: (value) => {
      information = value;
    },
    tokens: () => tokens,
    saveTokens: (value) => {
      tokens = value;
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
  await expectStatus(response, 200);
  const body = await response.json();
  assert.equal(body.redirect, true);
  return new URL(body.url, authURL);
}
async function consent(provider, target, requireLogin = false) {
  const authorization = provider.authorization();
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.equal(authorization.searchParams.get("resource"), target);
  if (requireLogin) cookie = "";
  let location = await redirectLocation(await ownerRequest(authorization));
  if (requireLogin) {
    assert.equal(location.pathname, "/login");
    const signedIn = await ownerRequest("/api/auth/sign-in/email", {
      email,
      password,
      oauth_query: location.search.slice(1),
    });
    await expectStatus(signedIn, 200);
    location = new URL((await signedIn.json()).url, authURL);
  }
  assert.equal(location.pathname, "/consent");
  const accepted = await ownerRequest("/api/auth/oauth2/consent", {
    accept: true,
    oauth_query: location.search.slice(1),
  });
  await expectStatus(accepted, 200);
  const callback = new URL((await accepted.json()).url);
  assert.equal(callback.searchParams.get("state"), "interop-state");
  assert.equal(callback.searchParams.get("iss"), issuer);
  return callback.searchParams;
}
async function authorize(target, scope, client, clientMetadataUrl) {
  const provider = providerFor(client, clientMetadataUrl);
  const options = {
    serverUrl: target,
    scope,
    fetchFn: routedFetch,
    resourceMetadataUrl: `${origin}/.well-known/oauth-protected-resource/${new URL(target).pathname.slice(1)}`,
  };
  assert.equal(await sdkAuth(provider, options), "REDIRECT");
  const callback = await consent(provider, target);
  assert.equal(
    await sdkAuth(provider, {
      ...options,
      authorizationCode: callback.get("code"),
      iss: callback.get("iss"),
    }),
    "AUTHORIZED",
  );
  return provider;
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

try {
  let handler;
  authServer = createServer(async (incoming, outgoing) => {
    try {
      if (incoming.url.startsWith("/api/auth/jwks")) jwksReads++;
      if (incoming.url === "/api/auth/oauth2/token") tokenRequests++;
      if (incoming.url === "/api/auth/oauth2/register") registrationRequests++;
      if (incoming.url.includes(".well-known")) discoveryReads.push(incoming.url);
      const chunks = [];
      for await (const chunk of incoming) chunks.push(chunk);
      const headers = new Headers();
      for (const [key, value] of Object.entries(incoming.headers))
        if (value) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
      const response = await handler(
        new Request(`${authURL}${incoming.url}`, {
          method: incoming.method,
          headers,
          body: ["GET", "HEAD"].includes(incoming.method) ? undefined : Buffer.concat(chunks),
        }),
      );
      outgoing.writeHead(response.status, {
        ...Object.fromEntries(response.headers),
        "set-cookie": response.headers.getSetCookie(),
      });
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      console.error("Auth listener failed:", error.message);
      outgoing.writeHead(500).end();
    }
  });
  await new Promise((done) => authServer.listen(0, "127.0.0.1", done));
  authURL = `http://127.0.0.1:${authServer.address().port}`;
  issuer = `${authURL}/api/auth`;
  const settings = {
    baseURL: authURL,
    secret: randomBytes(32).toString("hex"),
    database: join(directory, "auth.sqlite"),
    host: "127.0.0.1",
    port: authServer.address().port,
  };
  service = await openAuth(settings, {
    cimdTransport: async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      assert.equal(url, metadataUrl, "Only the fixed public metadata fixture may be requested");
      metadataFetches++;
      return Response.json(
        {
          client_id: metadataUrl,
          client_name: "Isolated CIMD interoperability",
          redirect_uris: ["http://127.0.0.1:9876/callback"],
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
        },
        { headers: { "cache-control": "max-age=300" } },
      );
    },
  });
  await initialize(service);
  handler = application(service);
  await expectStatus(await ownerRequest("/api/setup", { email, password }), 201);
  await expectStatus(await ownerRequest("/api/auth/sign-in/email", { email, password }), 200);
  for (const identifier of [resource, apiResource]) {
    await expectStatus(
      await ownerRequest("/admin/resources", {
        identifier,
        name: identifier,
        scopes: ["okf:read", "okf:write"],
      }),
      201,
    );
  }
  const session = await ownerRequest("/api/auth/get-session");
  await expectStatus(session, 200);
  const ownerSubject = (await session.json()).user.id;
  assert.ok(ownerSubject);
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
    auth: { issuer: new URL(issuer) },
    publicUrl: new URL(origin),
    bindHost: "127.0.0.1",
    port: 0,
  });
  for (const token of [undefined, "not-a-token"]) {
    const response = await call(token);
    await expectStatus(response, 401);
    assert.ok(response.headers.get("www-authenticate").includes("oauth-protected-resource/mcp"));
  }
  assert.equal(storageCalls, 0);
  console.log("PASS production missing/invalid token rejection; storageCalls=0");

  const provider = providerFor();
  const transport = new StreamableHTTPClientTransport(new URL(resource), {
    authProvider: provider,
    fetch: routedFetch,
  });
  const newSdk = () => {
    const client = new Client(
      { name: "okf-interop", version: "1.0.0" },
      {
        versionNegotiation: { mode: "auto" },
      },
    );
    clients.push(client);
    return client;
  };
  await assert.rejects(newSdk().connect(transport), (error) => error instanceof UnauthorizedError);
  assert.ok(discoveryReads.includes("/.well-known/oauth-protected-resource/mcp"));
  assert.ok(discoveryReads.some((path) => path.includes("oauth-authorization-server")));
  assert.equal(registrationRequests, 1);
  assert.ok(provider.clientInformation().client_id);
  const sharedClient = provider.clientInformation();
  const callback = await consent(provider, resource, true);
  const badCallback = new URLSearchParams(callback);
  badCallback.set("iss", "https://untrusted.interop.invalid");
  await assert.rejects(transport.finishAuth(badCallback), /issuer/i);
  assert.equal(tokenRequests, 0);
  await transport.finishAuth(callback);
  assert.equal(provider.tokens().issuer, issuer);
  assert.ok(provider.tokens().refresh_token);
  console.log(
    "PASS official SDK automatic DCR/challenge/discovery/login/consent/S256 exchange and callback issuer defense",
  );
  const connected = newSdk();
  const activeTransport = new StreamableHTTPClientTransport(new URL(resource), {
    authProvider: provider,
    fetch: routedFetch,
  });
  await connected.connect(activeTransport);
  const tools = await connected.listTools();
  assert.ok(tools.tools.some((tool) => tool.name === "create_bundle"));
  assert.ok(!provider.tokens().scope.split(" ").includes("okf:write"));
  const beforeUpgrade = storageCalls;
  await assert.rejects(
    connected.callTool({ name: "create_bundle", arguments: { repo: "interop", bundle: "mcp" } }),
    (error) => error instanceof UnauthorizedError,
  );
  assert.equal(storageCalls, beforeUpgrade);
  const upgradeScopes = provider.authorization().searchParams.get("scope").split(" ");
  assert.ok(upgradeScopes.includes("okf:read") && upgradeScopes.includes("okf:write"));
  const upgradeCallback = await consent(provider, resource);
  await activeTransport.finishAuth(upgradeCallback);
  const created = await connected.callTool({
    name: "create_bundle",
    arguments: { repo: "interop", bundle: "mcp" },
  });
  assert.ok(!created.isError, JSON.stringify(created));
  assert.ok(created.structuredContent.revision);
  console.log(
    "PASS read-only -> write challenge -> SDK scope upgrade/consent -> successful mutation",
  );
  assert.deepEqual(
    (await connected.callTool({ name: "list_repos", arguments: {} })).structuredContent,
    { repos: ["interop"] },
  );
  assert.ok(jwksReads > 0);
  console.log(
    `PASS production MCP tools/list (${tools.tools.length}), create_bundle/list_repos and JWKS fetch`,
  );

  const apiProvider = await authorize(
    apiResource,
    "okf:read okf:write offline_access",
    sharedClient,
  );
  let apiToken = apiProvider.tokens().access_token;
  let tokenCallbacks = 0;
  const api = createClient({
    baseUrl: origin,
    accessToken: () => {
      tokenCallbacks++;
      return apiToken;
    },
    agent: "untrusted-agent/1.0",
    session: "untrusted-session",
    fetch: (input, init) => {
      const headers = new Headers(init.headers);
      headers.set("Clanker-Actor", "human:forged");
      headers.set("X-Forwarded-User", "forged");
      return routedFetch(input, { ...init, headers });
    },
  });
  const apiCreated = await api.call("create_bundle", { repo: "interop", bundle: "api" });
  assert.ok(apiCreated.ok, JSON.stringify(apiCreated));
  assert.deepEqual(await api.call("list_repos", {}), { ok: true, value: { repos: ["interop"] } });
  for (const bundle of ["mcp", "api"]) {
    const history = await api.call("history", { repo: "interop", bundle });
    assert.ok(history.ok, JSON.stringify(history));
    assert.ok(history.value.changes.length > 0);
    for (const entry of history.value.changes)
      assert.equal(entry.actor, `human:${encodeURIComponent(ownerSubject)}`);
  }
  assert.equal(tokenCallbacks, 4);
  console.log(
    "PASS typed JSON API read/write, per-request token callback, history owner identity despite forged attribution",
  );
  const before = storageCalls;
  await expectStatus(await call(apiToken), 401);
  apiToken = provider.tokens().access_token;
  await assert.rejects(
    api.call("create_bundle", { repo: "blocked", bundle: "blocked" }),
    (error) =>
      error instanceof AuthenticationError &&
      error.status === 401 &&
      error.challenge.includes("oauth-protected-resource/api"),
  );
  const tampered = provider.tokens().access_token.split(".");
  tampered[1] = Buffer.from(
    JSON.stringify({ ...JSON.parse(Buffer.from(tampered[1], "base64url")), sub: "forged" }),
  ).toString("base64url");
  await expectStatus(await call(tampered.join(".")), 401);
  for (const token of ["not-a-token", tampered.join(".")]) {
    apiToken = token;
    await assert.rejects(
      api.call("list_repos", {}),
      (error) => error instanceof AuthenticationError && error.status === 401,
    );
  }
  assert.equal(storageCalls, before);
  console.log(
    "PASS both cross-surface audiences, invalid/tampered JWT and AuthenticationError; no additional storage calls",
  );
  for (const target of [resource, apiResource]) {
    const read = await authorize(target, "okf:read");
    if (target === resource) {
      const response = await call(read.tokens().access_token);
      await expectStatus(response, 403);
      assert.ok(response.headers.get("www-authenticate").includes("insufficient_scope"));
    } else {
      apiToken = read.tokens().access_token;
      await assert.rejects(
        api.call("create_bundle", { repo: "blocked", bundle: "blocked" }),
        (error) =>
          error instanceof AuthenticationError &&
          error.status === 403 &&
          error.challenge.includes("insufficient_scope"),
      );
    }
    assert.equal(storageCalls, before);
  }
  console.log("PASS MCP and API read-only write denial; no additional storage calls");
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
  console.log("PASS official SDK refresh rotation followed by production MCP read");
  const registrationsBeforeCimd = registrationRequests;
  const cimdProvider = await authorize(resource, "okf:read offline_access", undefined, metadataUrl);
  assert.equal(
    cimdProvider.discoveryState().authorizationServerMetadata.client_id_metadata_document_supported,
    true,
  );
  assert.equal(
    cimdProvider.discoveryState().authorizationServerMetadata.registration_endpoint,
    `${issuer}/oauth2/register`,
  );
  assert.ok(cimdProvider.clientInformation().client_id);
  assert.equal(cimdProvider.clientInformation().client_id, metadataUrl);
  assert.equal(registrationRequests, registrationsBeforeCimd);
  assert.equal(metadataFetches, 1);
  const cimdClaims = JSON.parse(
    Buffer.from(cimdProvider.tokens().access_token.split(".")[1], "base64url"),
  );
  assert.equal(cimdClaims.client_id, cimdProvider.clientInformation().client_id);
  const cimdClient = newSdk();
  await cimdClient.connect(
    new StreamableHTTPClientTransport(new URL(resource), {
      authProvider: cimdProvider,
      fetch: routedFetch,
    }),
  );
  assert.deepEqual(
    (await cimdClient.callTool({ name: "list_repos", arguments: {} })).structuredContent,
    { repos: ["interop"] },
  );
  const cimdRefresh = cimdProvider.tokens().refresh_token;
  assert.equal(
    await sdkAuth(cimdProvider, { serverUrl: resource, fetchFn: routedFetch }),
    "AUTHORIZED",
  );
  assert.notEqual(cimdProvider.tokens().refresh_token, cimdRefresh);
  assert.deepEqual(
    (await cimdClient.callTool({ name: "list_repos", arguments: {} })).structuredContent,
    { repos: ["interop"] },
  );
  console.log(
    "PASS official SDK CIMD without registration, metadata client_id JWT, MCP read and refresh rotation",
  );
  console.log(`OAUTH INTEROPERABILITY PASSED (${root}); only isolated fake storage used`);
} finally {
  for (const client of clients) await client.close().catch(() => {});
  if (upstream) await upstream.close();
  if (authServer) {
    authServer.closeAllConnections();
    await new Promise((done) => authServer.close(done));
  }
  if (service) await service.close();
  await rm(directory, { recursive: true, force: true });
}
