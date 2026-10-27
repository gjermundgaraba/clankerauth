import assert from "node:assert/strict";
import { once } from "node:events";
import { access, mkdtemp, readdir, rm } from "node:fs/promises";
import { createServer, request } from "node:http";
import type { IncomingMessage, OutgoingHttpHeaders } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Duplex } from "node:stream";
import { text } from "node:stream/consumers";
import { test } from "node:test";
import { setTimeout } from "node:timers/promises";

import { startDisposableIssuer } from "@gjermundgaraba/clankerauth-dev";
import type {
  DisposableIssuer,
  DisposableIssuerOptions,
} from "@gjermundgaraba/clankerauth-dev";
import {
  attach,
  reserveLoopbackPort,
} from "@gjermundgaraba/clankerauth-dev/edge";

type ResourceDefinition = DisposableIssuerOptions["resources"][number];

interface ObservedRequest {
  method: string;
  url: string;
}

type SocketAnswer =
  | { status: number | undefined }
  | { status: 101; head: Buffer; socket: Duplex };

interface Named {
  readonly name: string;
}

interface CreatedKey extends Named {
  readonly keyId: string;
  readonly key: string;
}

interface ResourceEntry {
  readonly identifier: string;
}

interface ClientEntry {
  readonly client_id: string;
  readonly token_endpoint_auth_method: string;
  readonly redirect_uris: readonly string[];
}

/** A `listClients` answer, as far as the suite reads it. */
interface Administration {
  readonly email: string;
  readonly resources: readonly ResourceEntry[];
  readonly clients: readonly ClientEntry[];
  readonly clientAccess: unknown;
}

interface AuthorizationServerMetadata {
  readonly jwks_uri: string;
  readonly registration_endpoint: string;
  readonly token_endpoint: string;
  readonly authorization_endpoint: string;
}

const isString = (value: unknown): value is string => typeof value === "string";

/** Anything `in` can probe: an object or an array, not `null` or another primitive. */
const isObject = (value: unknown): value is object =>
  typeof value === "object" && value !== null;

/** An array, with its elements still unread. */
const isArray = (value: unknown): value is unknown[] => Array.isArray(value);

const isNamed = (value: unknown): value is Named =>
  isObject(value) && "name" in value && isString(value.name);

const isCreatedKey = (value: unknown): value is CreatedKey =>
  isNamed(value) &&
  "keyId" in value &&
  isString(value.keyId) &&
  "key" in value &&
  isString(value.key);

const isResourceEntry = (value: unknown): value is ResourceEntry =>
  isObject(value) && "identifier" in value && isString(value.identifier);

const isClientEntry = (value: unknown): value is ClientEntry =>
  isObject(value) &&
  "client_id" in value &&
  isString(value.client_id) &&
  "token_endpoint_auth_method" in value &&
  isString(value.token_endpoint_auth_method) &&
  "redirect_uris" in value &&
  isArray(value.redirect_uris) &&
  value.redirect_uris.every(isString);

const isAdministration = (value: unknown): value is Administration =>
  isObject(value) &&
  "email" in value &&
  isString(value.email) &&
  "resources" in value &&
  isArray(value.resources) &&
  value.resources.every(isResourceEntry) &&
  "clients" in value &&
  isArray(value.clients) &&
  value.clients.every(isClientEntry) &&
  "clientAccess" in value;

const isAuthorizationServerMetadata = (
  value: unknown
): value is AuthorizationServerMetadata =>
  isObject(value) &&
  "jwks_uri" in value &&
  isString(value.jwks_uri) &&
  "registration_endpoint" in value &&
  isString(value.registration_endpoint) &&
  "token_endpoint" in value &&
  isString(value.token_endpoint) &&
  "authorization_endpoint" in value &&
  isString(value.authorization_endpoint);

/** Decode one base64url JSON segment of a compact JWT, failing the test unless `guard` accepts it. */
const decodeSegment = <Decoded,>(
  segment: string,
  guard: (value: unknown) => value is Decoded
): Decoded => {
  const decoded: unknown = JSON.parse(
    Buffer.from(segment, "base64url").toString()
  );

  assert.ok(guard(decoded));

  return decoded;
};

/** The part of `value` before the first `separator`, or all of it. */
const untilFirst = (value: string, separator: string) => {
  const end = value.indexOf(separator);

  return end === -1 ? value : value.slice(0, end);
};

/** The `name=value` pairs of a response's cookies, as a request's cookie header. */
const cookieHeader = (response: Response) =>
  response.headers
    .getSetCookie()
    .map((part) => untilFirst(part, ";"))
    .join("; ");

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

/** The keys a signed key list carries for one resource, or the status it was refused with. */
const listed = async (
  issuer: string,
  asked: string
): Promise<number | unknown[]> => {
  const response = await fetch(new URL("/api/keyList", issuer), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ resource: asked }),
  });

  if (response.status !== 200) {
    await response.body?.cancel();

    return response.status;
  }

  const body: unknown = await response.json();
  assert.ok(isObject(body) && "list" in body && isString(body.list));

  const [header, claims] = body.list
    .split(".")
    .slice(0, 2)
    .map((part) => decodeSegment(part, isObject));

  assert.partialDeepStrictEqual(header, { typ: "key-list+jwt" });
  assert.partialDeepStrictEqual(claims, { aud: asked });
  assert.ok(claims !== undefined && "keys" in claims && isArray(claims.keys));

  return claims.keys;
};

const login = async (
  issuer: DisposableIssuer,
  owner: DisposableIssuer["owner"] = issuer.owner
) =>
  await fetch(`${issuer.url}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { origin: issuer.url, "content-type": "application/json" },
    body: JSON.stringify(owner),
  });

await test("real HTTP issuer provisions resources and a confidential native client, refuses oversized bodies, and closes idempotently", async () => {
  const issuer = await startDisposableIssuer(options);

  try {
    assert.equal(new URL(issuer.url).hostname, "127.0.0.1");

    const metadata = await fetch(
      `${issuer.issuer}/.well-known/oauth-authorization-server`
    );

    const discovery: unknown = await metadata.json();

    assert.partialDeepStrictEqual(discovery, { issuer: issuer.issuer });
    const page = await fetch(issuer.url);
    assert.equal(page.status, 200);
    const contentType = page.headers.get("content-type");
    assert.ok(contentType !== null);
    assert.match(contentType, /text\/html/u);

    const setupStatus = await fetch(`${issuer.url}/api/setupStatus`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });

    const setup: unknown = await setupStatus.json();
    assert.partialDeepStrictEqual(setup, { required: false });

    const anonymousClients = await fetch(`${issuer.url}/api/listClients`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });

    assert.equal(anonymousClients.status, 401);
    const session = await login(issuer);
    assert.equal(session.status, 200);
    const cookie = cookieHeader(session);
    await session.body?.cancel();

    const clients = await fetch(`${issuer.url}/api/listClients`, {
      method: "POST",
      headers: {
        cookie,
        origin: issuer.url,
        "content-type": "application/json",
      },
      body: "{}",
    });

    const state: unknown = await clients.json();

    assert.ok(isAdministration(state));
    assert.equal(state.email, issuer.owner.email);
    assert.equal(state.resources.length, 2);
    assert.deepEqual(
      state.resources.find((item) => item.identifier === resource.identifier),
      { ...resource, builtIn: false }
    );
    assert.ok(
      state.resources.some((item) => item.identifier === `${issuer.url}/`)
    );
    assert.equal(state.clients.length, 1);
    assert.equal(state.clients[0]?.client_id, issuer.clientId);
    assert.equal(
      state.clients[0]?.token_endpoint_auth_method,
      "client_secret_basic"
    );
    assert.deepEqual(state.clients[0]?.redirect_uris, [
      options.client.redirect,
    ]);
    assert.ok(issuer.clientSecret);

    const oversized = await fetch(`${issuer.url}/api/setupOwner`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: issuer.url },
      body: "x".repeat(65_537),
    });

    assert.deepEqual([oversized.status, await oversized.text()], [413, ""]);
  } finally {
    await Promise.all([issuer.close(), issuer.close()]);
  }

  await assert.rejects(access(issuer.directory), { code: "ENOENT" });
  await assert.rejects(fetch(`${issuer.url}/healthz`));
});

await test("a cookie domain serves forward auth: the signed-in owner gets a resource token", async () => {
  const app = "http://app.notes.localhost:9876";

  const forwarded = {
    identifier: `${app}/api`,
    name: "Notes API",
    scopes: ["notes:read"],
  };

  const forward = async (issuer: DisposableIssuer, cookie: string) =>
    await fetch(
      `${issuer.url}/forward-auth?resource=${encodeURIComponent(forwarded.identifier)}`,
      {
        redirect: "manual",
        headers: {
          cookie,
          "x-forwarded-proto": "http",
          "x-forwarded-host": "app.notes.localhost:9876",
          "x-forwarded-uri": "/docs",
        },
      }
    );

  const issuer = await startDisposableIssuer({
    resources: [forwarded],
    client: { ...options.client, resources: [forwarded.identifier] },
    cookieDomain: "notes.localhost",
  });

  try {
    assert.equal(new URL(issuer.url).hostname, "clankerauth.notes.localhost");
    assert.equal(issuer.issuer, `${issuer.url}/api/auth`);
    // why: Node's fetch is a script's request, not a navigation, so it is refused in place.
    const anonymous = await forward(issuer, "");
    assert.equal(anonymous.status, 401);
    await anonymous.body?.cancel();
    const session = await login(issuer);
    assert.equal(session.status, 200);
    const cookie = cookieHeader(session);
    await session.body?.cancel();

    const proceed = await fetch(
      `${issuer.url}/forward-auth/continue?rd=${encodeURIComponent(`${app}/docs`)}`,
      { redirect: "manual", headers: { cookie } }
    );

    assert.equal(proceed.status, 302);
    assert.equal(proceed.headers.get("location"), `${app}/docs`);

    const shared = proceed.headers
      .getSetCookie()
      .find((part) => part.includes("Domain="));

    assert.ok(shared !== undefined);
    assert.match(shared, /Domain=notes\.localhost/u);
    const decision = await forward(issuer, untilFirst(shared, ";"));
    assert.equal(decision.status, 204);
    const authorization = decision.headers.get("authorization");
    assert.ok(authorization !== null);
    assert.match(authorization, /^Bearer /u);
  } finally {
    await issuer.close();
  }
});

await test("without a cookie domain the forward-auth routes are not served", async () => {
  const issuer = await startDisposableIssuer(options);

  try {
    const response = await fetch(`${issuer.url}/forward-auth?resource=x`);
    assert.equal(response.status, 404);
    await response.body?.cancel();
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
    await stale.body?.cancel();
    const fresh = await login(second);
    assert.equal(fresh.status, 200);
    await fresh.body?.cancel();
  } finally {
    await second.close();
  }

  await assert.rejects(access(second.directory), { code: "ENOENT" });
});

/** Wait for the first chunk a socket receives, as `once(socket, "data")` does. */
const firstChunk = async (socket: Duplex): Promise<Buffer> => {
  const { promise, resolve, reject } = Promise.withResolvers<unknown>();
  socket.once("data", resolve);
  socket.once("error", reject);
  const chunk = await promise;
  assert.ok(chunk instanceof Buffer);

  return chunk;
};

const directories = async () => {
  const names = await readdir(tmpdir());

  return names
    .filter((name) => name.startsWith("clankerauth-disposable-"))
    .toSorted();
};

/** Whether a server can listen on a loopback port again. */
const portFree = async (port: number) => {
  const probe = createServer();
  const listening = once(probe, "listening");
  probe.listen(port, "127.0.0.1");

  try {
    await listening;
  } catch {
    return false;
  }

  await probe[Symbol.asyncDispose]();

  return true;
};

await test("failed provisioning removes its temporary directory and listening server", async () => {
  const before = await directories();
  const port = await reserveLoopbackPort();

  await assert.rejects(
    startDisposableIssuer({
      ...options,
      port,
      resources: [{ ...resource, identifier: "invalid" }],
    }),
    /provisioning failed/u
  );
  assert.deepEqual(await directories(), before);
  assert.equal(await portFree(port), true);
});

await test("a start refused after binding, by an invalid cookieDomain, frees its port", async () => {
  const before = await directories();
  const port = await reserveLoopbackPort();

  await assert.rejects(
    startDisposableIssuer({ ...options, port, cookieDomain: "localhost" }),
    /CLANKERAUTH_COOKIE_DOMAIN/u
  );
  assert.deepEqual(await directories(), before);
  assert.equal(await portFree(port), true);
});

await test("close() does not wait for a request whose body never arrives", async () => {
  const issuer = await startDisposableIssuer(options);
  const { port } = new URL(issuer.url);
  const socket = connect(Number(port), "127.0.0.1");
  await once(socket, "connect");
  // why: a sign-in handler waits uninterruptibly on a body the client never sends.
  socket.write(
    `POST /api/auth/sign-in/email HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: ${issuer.url}\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n`
  );
  await setTimeout(100);
  const started = performance.now();
  await issuer.close();
  assert.ok(
    performance.now() - started < 5000,
    "close() waited for the request timeout"
  );
  socket.destroy();
  await assert.rejects(access(issuer.directory), { code: "ENOENT" });
});

await test("bundled provider lists key metadata without plaintext and keys for offline verification", async () => {
  const issuer = await startDisposableIssuer(options);

  try {
    const session = await login(issuer);
    assert.equal(session.status, 200);
    const cookie = cookieHeader(session);
    await session.body?.cancel();
    const headers = { cookie, "content-type": "application/json" };
    const created: CreatedKey[] = [];

    for (let index = 0; index < 3; index += 1) {
      const response = await fetch(`${issuer.url}/api/createApiKey`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: `Development key ${index}`,
          permissions: { [resource.identifier]: ["example:read"] },
          expiresAt: null,
        }),
      });

      assert.equal(response.status, 201);
      const key: unknown = await response.json();
      assert.ok(isCreatedKey(key));
      created.push(key);
    }

    const listResponse = await fetch(`${issuer.url}/api/listApiKeys`, {
      method: "POST",
      headers,
      body: "{}",
    });

    const listing: unknown = await listResponse.json();

    assert.ok(
      isObject(listing) &&
        "keys" in listing &&
        isArray(listing.keys) &&
        listing.keys.every(isNamed)
    );
    assert.deepEqual(
      listing.keys.map((key) => key.name),
      created.map((key) => key.name)
    );

    for (const key of created) {
      assert.ok(!JSON.stringify(listing).includes(key.key));
    }

    const entries = async () =>
      await listed(`${issuer.url}/api/auth`, resource.identifier);

    const active = await entries();
    assert.ok(isArray(active));
    assert.equal(active.length, created.length);

    const disabled = await fetch(`${issuer.url}/api/updateApiKey`, {
      method: "POST",
      headers,
      body: JSON.stringify({ keyId: created[0]?.keyId, enabled: false }),
    });

    assert.equal(disabled.status, 200);
    await disabled.body?.cancel();
    const remaining = await entries();
    assert.ok(isArray(remaining));
    assert.equal(remaining.length, created.length - 1);
  } finally {
    await issuer.close();
  }
});

await test("test hooks serve CIMD fixtures and observe real issuer HTTP requests, none of them provisioning", async () => {
  const requests: ObservedRequest[] = [];
  const metadataRequests: Request[] = [];
  const clientId = "https://fixture.example/oauth/client.json";
  const redirect = "http://127.0.0.1:8765/callback";

  const issuer = await startDisposableIssuer({
    ...options,
    onRequest(observed) {
      assert.deepEqual(Object.keys(observed).toSorted(), ["method", "url"]);
      assert.ok(observed.url instanceof URL);
      requests.push({ method: observed.method, url: observed.url.href });
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
    // why: `deepEqual` narrows its subject to the expected value's type, which for `[]` is `never[]`.
    assert.deepEqual<ObservedRequest[]>(requests, []);
    const discoveryURL = `${issuer.issuer}/.well-known/oauth-authorization-server`;
    const discoveryResponse = await fetch(discoveryURL);
    assert.equal(discoveryResponse.status, 200);
    const discovery: unknown = await discoveryResponse.json();
    assert.ok(isAuthorizationServerMetadata(discovery));
    const keys = await fetch(discovery.jwks_uri);
    assert.equal(keys.status, 200);
    const jwks: unknown = await keys.json();
    assert.ok(isObject(jwks) && "keys" in jwks && isArray(jwks.keys));

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
    const registered: unknown = await registration.json();
    assert.ok(
      isObject(registered) &&
        "client_id" in registered &&
        isString(registered.client_id)
    );

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
    await tokens.body?.cancel();
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
    const authorizationResult: unknown = await authorization.json();
    assert.ok(
      isObject(authorizationResult) &&
        "url" in authorizationResult &&
        isString(authorizationResult.url)
    );
    assert.match(authorizationResult.url, /\/login/u);
    assert.equal(metadataRequests.length, 1);
    assert.equal(metadataRequests[0]?.url, clientId);
    assert.equal(metadataRequests[0]?.method, "GET");
    assert.deepEqual(requests.at(-1), {
      method: "GET",
      url: authorizationURL.href,
    });
  } finally {
    await issuer.close();
  }
});

await test(
  "close interrupts an unfinished HTTP request and removes its database",
  { timeout: 10_000 },
  async () => {
    const issuer = await startDisposableIssuer(options);

    const pending = request(`${issuer.url}/healthz`, {
      headers: { Expect: "100-continue", "Content-Length": "1" },
    });

    const { promise: disconnected, resolve } = Promise.withResolvers();
    pending.on("error", resolve);
    pending.on("close", resolve);

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
  }
);

/** Sign the owner in and read the administration state. */
const administered = async (
  issuer: DisposableIssuer
): Promise<Administration> => {
  const session = await login(issuer);
  assert.equal(session.status, 200);
  await session.body?.cancel();
  const cookie = cookieHeader(session);

  const response = await fetch(`${issuer.url}/api/listClients`, {
    method: "POST",
    headers: {
      cookie,
      origin: issuer.url,
      "content-type": "application/json",
    },
    body: "{}",
  });

  const state: unknown = await response.json();
  assert.ok(isAdministration(state));

  return state;
};

await test("a data directory keeps the owner, the secret, the client, its access and the keys across restarts, and applies changed resources", async () => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "clankerauth-workspace-")
  );

  const port = await reserveLoopbackPort();
  const workspace = { ...options, dataDir: directory, port };
  const first = await startDisposableIssuer(workspace);

  const kept = async (
    issuer: DisposableIssuer,
    definition: ResourceDefinition
  ) => {
    const state = await administered(issuer);

    assert.equal(state.clients.length, 1);
    assert.equal(state.resources.length, 2);

    assert.deepEqual(
      state.resources.find((entry) => entry.identifier === resource.identifier),
      { ...definition, builtIn: false }
    );

    assert.deepEqual(state.clientAccess, [
      { client_id: first.clientId, resource: resource.identifier },
    ]);

    const keys = await listed(`${issuer.url}/api/auth`, resource.identifier);
    assert.ok(isArray(keys));
    assert.equal(keys.length, 1);
  };

  try {
    assert.equal(first.directory, directory);
    assert.equal(first.port, port);
    assert.equal(new URL(first.url).port, String(port));

    const key = await first.apiKey({
      permissions: { [resource.identifier]: ["example:read"] },
    });

    assert.match(key, /^clankerauth_/u);
    await first.close();
    await access(path.join(directory, "credentials.json"));

    const second = await startDisposableIssuer(workspace);

    try {
      assert.deepEqual(second.owner, first.owner);
      assert.equal(second.clientId, first.clientId);
      assert.equal(second.clientSecret, first.clientSecret);
      await kept(second, resource);
    } finally {
      await second.close();
    }

    const changed = {
      ...resource,
      name: "Renamed development API",
      scopes: [...resource.scopes, "example:admin"],
    };

    const third = await startDisposableIssuer({
      ...workspace,
      resources: [changed],
    });

    try {
      assert.equal(third.clientId, first.clientId);
      await kept(third, changed);
    } finally {
      await third.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

await test("owner sessions and tokens are provisioned without a hand-rolled cookie jar", async () => {
  const app = "http://app.notes.localhost:9877";

  const forwarded = {
    identifier: `${app}/`,
    name: "Notes",
    scopes: ["notes:read"],
  };

  const issuer = await startDisposableIssuer({
    resources: [forwarded],
    client: { ...options.client, resources: [forwarded.identifier] },
    cookieDomain: "notes.localhost",
  });

  try {
    const session = await issuer.ownerSession(app);
    assert.match(session.cookie, /clankerauth_forward=/u);
    assert.ok(
      session.cookies.some((entry) => entry.name === "clankerauth_forward")
    );

    const token = await issuer.ownerToken({
      resource: forwarded.identifier,
      appOrigin: app,
    });

    const [claims] = token
      .split(".")
      .slice(1, 2)
      .map((part) => decodeSegment(part, isObject));

    assert.partialDeepStrictEqual(claims, {
      aud: forwarded.identifier,
      client_id: "forward-auth",
      scope: "notes:read",
    });
  } finally {
    await issuer.close();
  }
});

await test("the forward-auth edge checks requests, proxies a socket and survives its errors", async () => {
  const port = await reserveLoopbackPort();
  const app = `http://app.notes.localhost:${port}`;

  const forwarded = {
    identifier: `${app}/`,
    name: "Notes",
    scopes: ["notes:read"],
  };

  const issuer = await startDisposableIssuer({
    resources: [forwarded],
    client: { ...options.client, resources: [forwarded.identifier] },
    cookieDomain: "notes.localhost",
  });

  const seen: Array<string | null> = [];
  const errors: string[] = [];
  // why: an upgraded socket is no longer its server's to close, so the test destroys each one.
  const sockets = new Set<Duplex>();

  const track = (socket: Duplex) => {
    sockets.add(
      socket.once("close", () => {
        sockets.delete(socket);
      })
    );
  };

  const upgradeHosts: Array<string | null> = [];

  const backend = createServer((incoming, outgoing) => {
    seen.push(incoming.headers.authorization ?? null);
    outgoing.writeHead(200, { "content-type": "text/plain" }).end("app");
  });

  backend.on("upgrade", (incoming, socket) => {
    track(socket);
    seen.push(incoming.headers.authorization ?? null);
    upgradeHosts.push(incoming.headers.host ?? null);
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    );
    socket.write("hello");
  });

  const backendListening = once(backend, "listening");
  backend.listen(0, "127.0.0.1");
  await backendListening;
  const address = backend.address();
  assert.ok(address instanceof Object);
  const backendUrl = `http://127.0.0.1:${address.port}`;

  const edge = createServer();

  const handle = attach(edge, {
    issuer: issuer.url,
    appOrigin: app,
    resource: forwarded.identifier,
    sockets: { backend: backendUrl, paths: ["/sync"] },
    onError: (error) => {
      errors.push(error.message);
    },
  });

  edge.on("request", (incoming, outgoing) => {
    handle(incoming, outgoing, () => {
      const upstream = request(
        `${backendUrl}${incoming.url}`,
        { headers: incoming.headers },
        (answer) => {
          assert.ok(answer.statusCode !== undefined);
          outgoing.writeHead(answer.statusCode, answer.headers);
          answer.pipe(outgoing);
        }
      );

      incoming.pipe(upstream);
    });
  });

  edge.on("upgrade", (incoming, socket) => {
    assert.ok(incoming.url !== undefined);
    const pathname = untilFirst(incoming.url, "?");

    if (pathname === "/sync" || pathname.startsWith("/sync/")) {
      return;
    }

    track(socket);
    socket.end("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
  });

  const edgeListening = once(edge, "listening");
  edge.listen(port, "127.0.0.1");
  await edgeListening;

  // why: `fetch` owns Sec-Fetch-Mode, the header that decides whether sign-in may redirect.
  const get = async (target: string, headers: OutgoingHttpHeaders = {}) => {
    const attempt = request(`http://127.0.0.1:${port}${target}`, { headers });

    const {
      promise: answered,
      resolve,
      reject,
    } = Promise.withResolvers<IncomingMessage>();

    attempt.once("response", resolve);
    attempt.once("error", reject);
    attempt.end();
    const answer = await answered;

    return {
      status: answer.statusCode,
      headers: answer.headers,
      body: await text(answer),
    };
  };

  try {
    const anonymous = await get("/docs");
    assert.equal(anonymous.status, 401);
    const contentType = anonymous.headers["content-type"];
    assert.ok(contentType !== undefined);
    assert.match(contentType, /application\/json/u);
    assert.deepEqual(JSON.parse(anonymous.body), { error: "unauthenticated" });
    // why: `deepEqual` narrows its subject to the expected value's type, which for `[]` is `never[]`.
    assert.deepEqual<Array<string | null>>(seen, []);

    const probe = await get("/healthz");
    assert.equal(probe.status, 200);
    assert.deepEqual<Array<string | null>>(seen, [null]);

    const { cookie } = await issuer.ownerSession(app);
    const admitted = await get("/docs", { cookie });
    assert.equal(admitted.status, 200);
    assert.equal(admitted.body, "app");
    const checked = seen.at(-1);
    assert.ok(isString(checked));
    assert.match(checked, /^Bearer /u);

    const navigation = await get("/docs", { "sec-fetch-mode": "navigate" });
    assert.equal(navigation.status, 302);
    const { location } = navigation.headers;
    assert.ok(location !== undefined);
    assert.match(location, /\/forward-auth\/continue/u);

    const openSocket = async (target: string, headers: OutgoingHttpHeaders) => {
      const { promise, resolve, reject } =
        Promise.withResolvers<SocketAnswer>();

      const attempt = request(`http://127.0.0.1:${port}${target}`, {
        headers: { connection: "Upgrade", upgrade: "websocket", ...headers },
      });

      attempt.on("upgrade", (_answer, socket, head) => {
        track(socket);
        resolve({ status: 101, head, socket });
      });
      attempt.on("response", (answer) => {
        answer.resume();
        resolve({ status: answer.statusCode });
      });
      attempt.on("error", reject);
      attempt.end();

      return await promise;
    };

    const refused = await openSocket("/sync", {});
    assert.equal(refused.status, 401);

    const proxied = await openSocket("/sync", { cookie });
    assert.equal(proxied.status, 101);
    assert.ok("socket" in proxied);

    const greeting =
      proxied.head.length > 0 ? proxied.head : await firstChunk(proxied.socket);

    assert.equal(String(greeting), "hello");
    const relayed = seen.at(-1);
    assert.ok(isString(relayed));
    assert.match(relayed, /^Bearer /u);
    assert.equal(upgradeHosts.at(-1), `127.0.0.1:${port}`);
    proxied.socket.destroy();

    const untouched = await openSocket("/hmr", { cookie });
    assert.equal(untouched.status, 200);

    await issuer.close();
    const broken = await get("/docs", { cookie });
    assert.equal(broken.status, 502);
  } finally {
    for (const socket of sockets) {
      socket.destroy();
    }

    const stopped = Promise.all([
      edge[Symbol.asyncDispose](),
      backend[Symbol.asyncDispose](),
    ]);

    edge.closeAllConnections();
    backend.closeAllConnections();
    await stopped;
    await issuer.close();
  }
});
