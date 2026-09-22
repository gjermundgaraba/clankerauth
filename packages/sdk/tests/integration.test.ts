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
import {
  authenticationErrors,
  InsufficientScope,
  ProviderUnavailable,
  Unauthorized,
} from "../src/errors.ts";
import { Session } from "../src/session.ts";
import { CurrentPrincipal, Resource } from "../src/effect-actions.ts";
import { publicUrl, startIssuer } from "./issuer.ts";
import { withHttp } from "./support.ts";

// One resource per app, at the origin root, so /api, /mcp and a socket share it.
const resourceId = `${publicUrl}/`;

const Actions = ActionGroup.make(
  { name: "notes" },
  Action.make("identity", {
    description: "Fixture action",
    access: "read",
    success: Schema.String,
  }),
  Action.make("write", { description: "Fixture action", access: "write", success: Schema.String }),
);

// The surface renders every refusal itself, so a typed client decodes them.
const Http = ActionHttp.make({ apiPath: "/api", errors: authenticationErrors }, Actions, Session);

const identity = Effect.map(CurrentPrincipal, (principal) =>
  principal.actor.kind === "key" ? principal.actor.keyId : principal.actor.clientId,
);

test("one resource protects HTTP and MCP, and the hook is the only authorization code", async () => {
  const issuer = await startIssuer();

  const resource = await Effect.runPromise(
    withHttp(
      Resource.make({
        issuer: issuer.issuer,
        publicUrl: new URL(publicUrl),
        scopes: { read: "notes:read", write: "notes:write" },
      }),
    ),
  );

  const app = Actions.implement({
    identity: () => identity,
    write: () => Effect.succeed("written"),
  });

  const web = HttpRouter.toWebHandler(
    Layer.mergeAll(
      resource.discovery.layer,
      Http.layer([app, resource.session], { before: resource.authorize }).pipe(
        Layer.provide(Resource.middleware(resource).layer),
      ),
      ActionMcp.layerHttp([app], {
        name: "notes",
        version: "1.0.0",
        path: "/mcp",
        protocols: [McpProtocol.v2026_07_28],
        errors: authenticationErrors,
        before: resource.authorize,
      }).pipe(Layer.provide(Resource.middleware(resource).layer)),
    ).pipe(Layer.provide(HttpServer.layerServices)),
  );

  const call = (name: string, token?: string) => {
    const headers = new Headers({ "content-type": "application/json" });

    if (token) headers.set("authorization", `Bearer ${token}`);

    return web.handler(
      new Request(`${publicUrl}/api/${name}`, { method: "POST", headers, body: "{}" }),
    );
  };

  try {
    const missing = await call("notes/identity");
    assert.equal(missing.status, 401);
    assert.equal(missing.headers.get("cache-control"), "no-store");
    assert.match(missing.headers.get("www-authenticate") ?? "", /oauth-protected-resource"/u);
    assert.doesNotMatch(missing.headers.get("www-authenticate") ?? "", /error=/u);
    assert.deepEqual(
      await missing.json(),
      Schema.encodeSync(Unauthorized)(new Unauthorized({ message: "Authentication required" })),
    );

    const identities = await Promise.all(
      [issuer.key, issuer.readOnlyKey].map(async (token) =>
        (await call("notes/identity", token)).json(),
      ),
    );

    assert.deepEqual(identities, ["writer", "reader"]);
    assert.equal(await (await call("notes/write", issuer.key)).json(), "written");

    // The session group is the SDK's own, answered from the verified credential.
    assert.deepEqual(await (await call("session/whoami", issuer.readOnlyKey)).json(), {
      subject: "owner",
      issuer: issuer.issuer,
      scopes: ["notes:read"],
    });

    // The hook refuses the write and names only the scope the credential lacks.
    const refused = await call("notes/write", issuer.readOnlyKey);
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
    const limited = await call("notes/identity", issuer.key);
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get("retry-after"), "60");
    assert.equal(limited.headers.get("www-authenticate"), null);
    issuer.fail(503);
    const unavailable = await call("notes/identity", issuer.key);
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
