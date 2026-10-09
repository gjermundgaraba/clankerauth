import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import { Effect, Layer, Logger, Result, Schema } from "effect";
import {
  FetchHttpClient,
  HttpClient,
  HttpClientRequest,
  HttpRouter,
  HttpServer,
  HttpServerResponse,
} from "effect/http";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import * as Testing from "@gjermundgaraba/effect-actions/Testing";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import { ProviderUnavailable } from "../src/errors.ts";
import { CurrentPrincipal, Whoami } from "../src/session.ts";
import { Resource } from "../src/effect-actions.ts";
import { startFakeIssuer } from "../src/testing.ts";
import { authorize, Login, Notes, publicUrl, sent, startIssuer } from "./support.ts";

// One resource per app, at the origin root, so /api, /mcp and a socket share it.
const resourceId = `${publicUrl}/`;

const Identity = Action.make("identity", {
  description: "Fixture action",
  readOnly: true,
  caller: CurrentPrincipal,
  success: Schema.String,
});

const Write = Action.make("write", {
  description: "Fixture action",
  readOnly: false,
  caller: CurrentPrincipal,
  success: Schema.String,
});

// Refusals are built in on every endpoint; the descriptor declares the one answer that is the
// verifier's own, so every protected endpoint declares it and a typed client decodes it too.
const Http = ActionHttp.make([Identity, Write, Whoami], { authentication: Login });

const identity = Effect.map(CurrentPrincipal, ({ actor }) => {
  switch (actor.kind) {
    case "key":
      return actor.keyId;
    case "client":
      return actor.clientId;
    case "local":
      return "local";
  }
});

test("one resource protects HTTP and MCP, and the application's one rule authorizes both", async () => {
  const issuer = await startIssuer(resourceId);

  const app = Action.implement(
    [Identity, Write],
    { identity: () => identity, write: () => Effect.succeed("written") },
    { authorize },
  );

  // The resource's layer also publishes discovery: no route of its own.
  const web = HttpRouter.toWebHandler(
    Layer.mergeAll(
      ActionHttp.layer(Http, [app, Notes.session]),
      ActionMcp.layerHttp(app, { name: "notes", version: "1.0.0", authentication: Login }),
    ).pipe(
      Layer.provide(Notes.provider),
      Layer.provide(
        Notes.layer({
          issuer: issuer.issuer,
          publicUrl: new URL(publicUrl),
        }),
      ),
      Layer.provide(FetchHttpClient.layer),
      Layer.provide(HttpServer.layerServices),
    ),
  );

  const call = (name: string, token?: string) => {
    const headers = new Headers({ "content-type": "application/json" });

    if (token) headers.set("authorization", `Bearer ${token}`);

    return web.handler(
      new Request(`${publicUrl}/api/${name}`, { method: "POST", headers, body: "{}" }),
    );
  };

  try {
    const missing = await call("identity");
    assert.equal(missing.status, 401);
    // The scope every credential must carry, which a first login requests.
    assert.match(missing.headers.get("www-authenticate") ?? "", /scope="notes:read"/u);

    const identities = await Promise.all(
      [issuer.key, issuer.readOnlyKey].map(async (token) => (await call("identity", token)).json()),
    );

    assert.deepEqual(identities, ["key-1", "key-2"]);
    assert.equal(await (await call("write", issuer.key)).json(), "written");

    // `whoami` is the SDK's own, answered from the verified credential.
    assert.deepEqual(await (await call("whoami", issuer.readOnlyKey)).json(), {
      subject: "owner",
      issuer: issuer.issuer,
      scopes: ["notes:read"],
    });

    // The application's rule refuses the write. A key cannot step up, so its refusal is a plain 403.
    const refused = await call("write", issuer.readOnlyKey);
    assert.equal(refused.status, 403);
    assert.deepEqual(
      await refused.json(),
      sent(new Action.Forbidden({ message: "Requires notes:write." })),
    );

    // An access token can: its 403 names only the scope it lacks.
    const stepUp = await call("write", await issuer.sign({ scope: "notes:read" }));
    assert.equal(stepUp.status, 403);
    assert.deepEqual(
      await stepUp.json(),
      sent(new Action.Forbidden({ message: "Requires notes:write.", scopes: ["notes:write"] })),
    );

    // RFC 9728: one resource with no path, one discovery document, for every surface.
    const metadata = await web.handler(
      new Request(`${publicUrl}/.well-known/oauth-protected-resource`),
    );

    assert.equal(metadata.status, 200);
    const { resource, authorization_servers, scopes_supported } = await metadata.json();
    assert.deepEqual(
      { resource, authorization_servers, scopes_supported },
      {
        resource: resourceId,
        authorization_servers: [issuer.issuer],
        scopes_supported: ["notes:read", "notes:write"],
      },
    );

    // A `tools/list` as a web `Request`, answered by the handler under test.
    const mcp = (headers: Record<string, string>) =>
      web.handler(
        Result.getOrThrow(
          HttpClientRequest.toWebResult(
            Testing.mcpRequest("tools/list", undefined, { url: `${publicUrl}/mcp`, headers }),
          ),
        ),
      );

    assert.equal((await mcp({ authorization: `Bearer ${await issuer.sign()}` })).status, 200);

    // The same hook runs on MCP. A key's refusal is the tool's failure, as typed as HTTP's.
    const asKey = HttpClient.mapRequest(HttpClientRequest.bearerToken(issuer.readOnlyKey));

    const refusedTool = await Effect.runPromise(
      Effect.gen(function* () {
        const tools = yield* Testing.mcpClient(app.actions, {
          url: `${publicUrl}/mcp`,
          transformClient: asKey,
        });

        return yield* Effect.flip(tools.write());
      }).pipe(Effect.provide(Testing.layer(web.handler))),
    );

    assert(refusedTool instanceof Action.Forbidden);
    assert.equal(refusedTool.scopes, undefined);

    // An outage after the key list was read changes nothing for a key.
    issuer.fail(503);
    assert.equal((await call("identity", issuer.key)).status, 200);
  } finally {
    await web.dispose();
    await issuer.close();
  }
});

test("a surface without discovery authenticates and publishes nothing", async () => {
  const issuer = await startIssuer(resourceId);

  const app = Action.implement(Identity, () => identity, { authorize });

  const web = HttpRouter.toWebHandler(
    ActionHttp.layer(Http, app).pipe(
      Layer.provide(Notes.provider),
      Layer.provide(
        Notes.layer({
          issuer: issuer.issuer,
          publicUrl: new URL(publicUrl),

          discovery: false,
        }),
      ),
      Layer.provide(FetchHttpClient.layer),
      Layer.provide(HttpServer.layerServices),
    ),
  );

  const call = (authorization?: string) => {
    const headers = new Headers({ "content-type": "application/json" });

    if (authorization !== undefined) headers.set("authorization", authorization);

    return web.handler(
      new Request(`${publicUrl}/api/identity`, { method: "POST", headers, body: "{}" }),
    );
  };

  try {
    assert.equal((await call(`Bearer ${issuer.key}`)).status, 200);

    // No metadata is published.
    const missing = await call();
    assert.equal(missing.status, 401);

    assert.equal(
      (await web.handler(new Request(`${publicUrl}/.well-known/oauth-protected-resource`))).status,
      404,
    );
  } finally {
    await web.dispose();
    await issuer.close();
  }
});

test("a listener publishing discovery warns once when reached at another host", async () => {
  const issuer = await startIssuer(resourceId);

  const app = Action.implement(Identity, () => identity, { authorize });

  const warnings: Array<string> = [];

  const capture = Logger.make(({ logLevel, message }) => {
    if (logLevel === "Warn") warnings.push(String(message));
  });

  const listener = (discovery: boolean) =>
    HttpRouter.toWebHandler(
      ActionHttp.layer(Http, app).pipe(
        Layer.provide(Notes.provider),
        Layer.provide(
          Notes.layer({ issuer: issuer.issuer, publicUrl: new URL(publicUrl), discovery }),
        ),
        Layer.provide(FetchHttpClient.layer),
        Layer.provide(HttpServer.layerServices),
        Layer.provide(Logger.layer([capture])),
      ),
    );

  const call = (web: ReturnType<typeof listener>, host: string) =>
    web.handler(
      new Request(`${publicUrl}/api/identity`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host,
          authorization: `Bearer ${issuer.key}`,
        },
        body: "{}",
      }),
    );

  const publishing = listener(true);
  const beside = listener(false);

  try {
    assert.equal((await call(publishing, new URL(publicUrl).host)).status, 200);
    assert.deepEqual(warnings, []);

    // Keys keep working at any host; only discovery there is broken, so it is said once.
    assert.equal((await call(publishing, "notes.elsewhere.example")).status, 200);
    assert.equal((await call(publishing, "notes.elsewhere.example")).status, 200);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0] ?? "", /notes\.elsewhere\.example/u);

    // A listener beside it publishes nothing, so its own host is not the resource's.
    assert.equal((await call(beside, "notes.elsewhere.example")).status, 200);
    assert.equal(warnings.length, 1);
  } finally {
    await publishing.dispose();
    await beside.dispose();
    await issuer.close();
  }
});

const Admin = Resource.make(
  Authentication.make("fixture.admin", CurrentPrincipal, { error: ProviderUnavailable }),
  { scopes: ["notes:read", "notes:write"], required: "notes:read" },
);

// A single-scope resource: verification is its whole policy.
const Machine = Resource.make(
  Authentication.make("fixture.machine", CurrentPrincipal, { error: ProviderUnavailable }),
  { scopes: ["notes:machine"], required: "notes:machine" },
);

const AdminHttp = ActionHttp.make([Identity, Write, Whoami], {
  authentication: Admin.authentication,
});

const MachineHttp = ActionHttp.make([Identity], {
  prefix: "/machine",
  authentication: Machine.authentication,
});

// Module-level implementations, each behind its own application rule.
const admin = Action.implement(
  [Identity, Write],
  { identity: () => identity, write: () => Effect.succeed("written") },
  {
    authorize: (action) => (action.readOnly ? Effect.void : Admin.requires("notes:write")),
  },
);

const machine = Action.implement(Identity, () => identity, { authorize: Action.allowAll });

test.for(["admin first", "machine first"] as const)(
  "two resources in one layer graph each guard their own surface, built %s",
  async (order) => {
    const issuer = await startFakeIssuer({
      resource: resourceId,
      scopes: ["notes:read", "notes:write", "notes:machine"],
    });

    const options = { issuer: issuer.issuer, publicUrl: new URL(publicUrl) };

    const adminSurface = ActionHttp.layer(AdminHttp, [admin, Admin.session]).pipe(
      Layer.provide(Admin.provider),
      Layer.provide(Admin.layer(options)),
    );

    const machineSurface = ActionHttp.layer(MachineHttp, machine).pipe(
      Layer.provide(Machine.provider),
      Layer.provide(Machine.layer({ ...options, discovery: false })),
    );

    // One handler, one layer graph, no `Layer.fresh`: each surface still reads its own.
    const web = HttpRouter.toWebHandler(
      (order === "admin first"
        ? Layer.mergeAll(adminSurface, machineSurface)
        : Layer.mergeAll(machineSurface, adminSurface)
      ).pipe(Layer.provide(FetchHttpClient.layer), Layer.provide(HttpServer.layerServices)),
    );

    const call = (path: string, token: string) =>
      web.handler(
        new Request(`${publicUrl}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
          body: "{}",
        }),
      );

    try {
      const reader = await issuer.sign({ scope: "notes:read" });
      const machineToken = await issuer.sign({ scope: "notes:machine" });

      // Each surface verifies against its own resource's scopes and enforces its own rule.
      assert.equal((await call("/api/identity", reader)).status, 200);
      assert.equal((await call("/api/identity", machineToken)).status, 403);
      assert.equal((await call("/api/write", reader)).status, 403);
      assert.equal((await call("/api/whoami", reader)).status, 200);
      assert.equal((await call("/machine/identity", machineToken)).status, 200);
      assert.equal((await call("/machine/identity", reader)).status, 403);

      // Only the resource that publishes answers discovery.
      const discovery = await web.handler(
        new Request(`${publicUrl}/.well-known/oauth-protected-resource`),
      );

      assert.equal(discovery.status, 200);
      assert.deepEqual((await discovery.json()).scopes_supported, ["notes:read", "notes:write"]);
    } finally {
      await web.dispose();
      await issuer.close();
    }
  },
);

test("admitted(scope) refuses a host's own route as the action requiring the scope is refused", async () => {
  const issuer = await startIssuer(resourceId);

  const app = Action.implement(
    [Identity, Write],
    { identity: () => identity, write: () => Effect.succeed("written") },
    { authorize },
  );

  // A route of the host's own reads its caller as a handler does.
  const subject = Effect.map(CurrentPrincipal, (principal) =>
    HttpServerResponse.text(principal.subject),
  );

  const web = HttpRouter.toWebHandler(
    Layer.mergeAll(
      ActionHttp.layer(Http, app),
      HttpRouter.add("PUT", "/upload", subject).pipe(
        Layer.provide(Notes.admitted("notes:write").layer),
      ),
    ).pipe(
      // One provider for actions and routes alike: `admitted` authenticates with it.
      Layer.provide(Notes.provider),
      Layer.provide(Notes.layer({ issuer: issuer.issuer, publicUrl: new URL(publicUrl) })),
      Layer.provide(FetchHttpClient.layer),
      Layer.provide(HttpServer.layerServices),
    ),
  );

  const headers = (authorization: string | undefined): Record<string, string> =>
    authorization === undefined ? {} : { authorization };

  const write = (authorization?: string) =>
    web.handler(
      new Request(`${publicUrl}/api/write`, {
        method: "POST",
        headers: { ...headers(authorization), "content-type": "application/json" },
        body: "{}",
      }),
    );

  const upload = (authorization?: string) =>
    web.handler(
      new Request(`${publicUrl}/upload`, { method: "PUT", headers: headers(authorization) }),
    );

  const seen = async (response: Response) => ({
    status: response.status,
    challenge: response.headers.get("www-authenticate"),
    body: await response.json(),
  });

  try {
    const stepUpToken = await issuer.sign({ scope: "notes:read" });

    // No credential, a key without the scope, and a client that can step up to it.
    for (const authorization of [
      undefined,
      `Bearer ${issuer.readOnlyKey}`,
      `Bearer ${stepUpToken}`,
    ]) {
      const expected = await seen(await write(authorization));

      assert.notEqual(expected.status, 200);
      assert.deepEqual(await seen(await upload(authorization)), expected, `${authorization}`);
    }

    // A caller holding the scope reaches the route, as itself.
    const written = await upload(`Bearer ${issuer.key}`);
    assert.equal(written.status, 200);
    assert.equal(await written.text(), "owner");
  } finally {
    await web.dispose();
    await issuer.close();
  }
});
