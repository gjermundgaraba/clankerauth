import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import { Effect, Layer, Schema } from "effect";
import { McpProtocol } from "effect/unstable/ai";
import { HttpRouter, HttpServer } from "effect/unstable/http";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionGroup from "@gjermundgaraba/effect-actions/ActionGroup";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import { mcpRequest } from "@gjermundgaraba/effect-actions/Testing";
import { InsufficientScope, ProviderUnavailable, RateLimited, Unauthorized } from "../src/index.ts";
import { CurrentPrincipal, Resource } from "../src/effect-actions.ts";
import { publicUrl, startIssuer } from "./issuer.ts";
import { withHttp } from "./support.ts";

// One resource per app, at the origin root, so /api, /mcp and a socket share it.
const resourceId = `${publicUrl}/`;

const Actions = ActionGroup.make(
  { name: "notes", errors: [InsufficientScope] },
  Action.make("identity", {
    description: "Fixture action",
    access: "read",
    success: Schema.String,
  }),
  Action.make("write", { description: "Fixture action", access: "write", success: Schema.String }),
);

// The surface renders these itself, so a typed client decodes them.
const Http = ActionHttp.make(
  { apiPath: "/api", errors: [Unauthorized, RateLimited, ProviderUnavailable] },
  Actions,
);

const identity = Effect.map(CurrentPrincipal, (principal) =>
  principal.actor.kind === "key" ? principal.actor.keyId : principal.actor.clientId,
);

test("one resource protects HTTP and MCP, and the hook is the only authorization code", async () => {
  const issuer = await startIssuer();

  const resource = await Effect.runPromise(
    withHttp(
      Resource.make({
        issuer: issuer.issuer,
        resource: resourceId,
        scopes: ["notes:read", "notes:write"],
        requiredScopes: ["notes:read"],
        writeScope: "notes:write",
      }),
    ),
  );

  const app = Actions.implement(
    { identity: () => identity, write: () => Effect.succeed("written") },
    { before: resource.authorize },
  );

  const web = HttpRouter.toWebHandler(
    Layer.mergeAll(
      resource.discovery.layer,
      Http.layer(app).pipe(Layer.provide(Resource.middleware(resource).layer)),
      ActionMcp.layerHttp(
        { name: "notes", version: "1.0.0", path: "/mcp", protocols: [McpProtocol.v2026_07_28] },
        app,
      ).pipe(Layer.provide(Resource.middleware(resource).layer)),
    ).pipe(Layer.provide(HttpServer.layerServices)),
  );

  const call = (name: string, token?: string) => {
    const headers = new Headers({ "content-type": "application/json" });

    if (token) headers.set("authorization", `Bearer ${token}`);

    return web.handler(
      new Request(`${publicUrl}/api/notes/${name}`, { method: "POST", headers, body: "{}" }),
    );
  };

  try {
    const missing = await call("identity");
    assert.equal(missing.status, 401);
    assert.equal(missing.headers.get("cache-control"), "no-store");
    assert.match(missing.headers.get("www-authenticate") ?? "", /oauth-protected-resource"/u);
    assert.doesNotMatch(missing.headers.get("www-authenticate") ?? "", /error=/u);
    assert.deepEqual(
      await missing.json(),
      Schema.encodeSync(Unauthorized)(new Unauthorized({ message: "Authentication required" })),
    );

    const identities = await Promise.all(
      [issuer.key, issuer.readOnlyKey].map(async (token) => (await call("identity", token)).json()),
    );

    assert.deepEqual(identities, ["writer", "reader"]);
    assert.equal(await (await call("write", issuer.key)).json(), "written");

    // The hook refuses the write and names only the scope the credential lacks.
    const refused = await call("write", issuer.readOnlyKey);
    assert.equal(refused.status, 403);
    assert.deepEqual(
      await refused.json(),
      Schema.encodeSync(InsufficientScope)(new InsufficientScope({ scope: "notes:write" })),
    );

    // RFC 9728: one resource with no path, one discovery document, for every surface.
    const metadata = await web.handler(
      new Request(`${publicUrl}/.well-known/oauth-protected-resource`),
    );

    assert.equal(metadata.status, 200);
    assert.deepEqual(await metadata.json(), {
      resource: resourceId,
      authorization_servers: [issuer.issuer],
      scopes_supported: ["notes:read", "notes:write"],
      bearer_methods_supported: ["header"],
    });

    const tools = mcpRequest({ url: `${publicUrl}/mcp`, method: "tools/list" });
    tools.headers.set("cookie", "notes_session=not-a-bearer");
    assert.equal((await web.handler(tools)).status, 401);
    const authorized = mcpRequest({ url: `${publicUrl}/mcp`, method: "tools/list" });
    authorized.headers.set("authorization", `Bearer ${await issuer.sign({}, "")}`);
    assert.equal((await web.handler(authorized)).status, 200);

    // The same hook runs on MCP: a refusal is the tool's declared failure.
    const mcpWrite = mcpRequest({
      url: `${publicUrl}/mcp`,
      method: "tools/call",
      params: { name: "write", arguments: {} },
    });

    mcpWrite.headers.set(
      "authorization",
      `Bearer ${await issuer.sign({ scope: "notes:read" }, "")}`,
    );

    const mcpResult = (await (await web.handler(mcpWrite)).json()).result;
    assert.equal(mcpResult.isError, true);
    assert.deepEqual(mcpResult.content, [
      { type: "text", text: '{"_tag":"InsufficientScope","scope":"notes:write"}' },
    ]);

    issuer.fail(429);
    const limited = await call("identity", issuer.key);
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get("retry-after"), "60");
    assert.equal(limited.headers.get("www-authenticate"), null);
    issuer.fail(503);
    const unavailable = await call("identity", issuer.key);
    assert.equal(unavailable.status, 503);
    assert.deepEqual(
      await unavailable.json(),
      Schema.encodeSync(ProviderUnavailable)(
        new ProviderUnavailable({ operation: "api-key.verify" }),
      ),
    );
  } finally {
    await web.dispose();
    await issuer.close();
  }
});
