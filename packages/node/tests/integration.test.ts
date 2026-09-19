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
import { Forbidden, ProviderUnavailable, Unauthorized } from "../src/index.ts";
import { CurrentPrincipal, Resource } from "../src/effect-actions.ts";
import { publicUrl, startIssuer } from "./issuer.ts";
import { run, withHttp } from "./support.ts";

const Actions = ActionGroup.make(
  { name: "notes", errors: [Forbidden] },
  Action.make("identity", {
    description: "Fixture action",
    success: Schema.String,
    mcp: { readOnly: true },
  }),
  Action.make("write", { description: "Fixture action", success: Schema.String }),
);

const Http = ActionHttp.make({ apiPath: "/api" }, Actions);

const app = Actions.implement({
  identity: () =>
    Effect.map(CurrentPrincipal, (principal) =>
      principal.actor.kind === "key" ? principal.actor.keyId : principal.actor.clientId,
    ),
  write: () =>
    Effect.gen(function* () {
      const principal = yield* CurrentPrincipal;

      if (!principal.scopes.includes("notes:write"))
        return yield* new Forbidden({ message: "Write permission required" });

      return "written";
    }),
});

test("effect-actions HTTP/MCP middleware supplies isolated principals and public discovery", async () => {
  const issuer = await startIssuer();

  const api = await run(
    withHttp(
      Resource.make({
        issuer: issuer.issuer,
        resource: `${publicUrl}/api`,
        scopes: ["notes:read", "notes:write"],
        requiredScopes: ["notes:read"],
      }),
    ),
  );

  const mcp = await run(
    withHttp(
      Resource.make({
        issuer: issuer.issuer,
        resource: `${publicUrl}/mcp`,
        scopes: ["notes:read", "notes:write"],
        requiredScopes: ["notes:read"],
      }),
    ),
  );

  const web = HttpRouter.toWebHandler(
    Layer.mergeAll(
      api.discovery.layer,
      mcp.discovery.layer,
      Http.layer(app).pipe(Layer.provide(api.middleware.layer)),
      ActionMcp.layerHttp(
        { name: "notes", version: "1.0.0", path: "/mcp", protocols: [McpProtocol.v2026_07_28] },
        app,
      ).pipe(Layer.provide(mcp.middleware.layer)),
    ).pipe(Layer.provide(HttpServer.layerServices)),
  );

  const call = (name: string, token?: string) => {
    const headers = new Headers({ "content-type": "application/json" });

    if (token) headers.set("authorization", `Bearer ${token}`);

    return web.handler(
      new Request(`${publicUrl}/api/notes/${name}`, {
        method: "POST",
        headers,
        body: "{}",
      }),
    );
  };

  try {
    const missing = await call("identity");
    assert.equal(missing.status, 401);
    assert.equal(missing.headers.get("cache-control"), "no-store");
    assert.match(missing.headers.get("www-authenticate") ?? "", /oauth-protected-resource\/api/);
    assert.deepEqual(
      await missing.json(),
      Schema.encodeSync(Unauthorized)(new Unauthorized({ message: "Authentication required" })),
    );

    const identities = await Promise.all(
      [issuer.key, issuer.readOnlyKey].map(async (token) => (await call("identity", token)).json()),
    );

    assert.deepEqual(identities, ["writer", "reader"]);
    assert.equal((await call("write", issuer.readOnlyKey)).status, 403);

    for (const surface of ["api", "mcp"]) {
      const metadata = await web.handler(
        new Request(`${publicUrl}/.well-known/oauth-protected-resource/${surface}`),
      );

      assert.equal(metadata.status, 200);
      assert.deepEqual(await metadata.json(), {
        resource: `${publicUrl}/${surface}`,
        authorization_servers: [issuer.issuer],
        scopes_supported: ["notes:read", "notes:write"],
        bearer_methods_supported: ["header"],
      });
    }

    const tools = mcpRequest({ url: `${publicUrl}/mcp`, method: "tools/list" });
    tools.headers.set("cookie", "notes_session=not-a-bearer");
    assert.equal((await web.handler(tools)).status, 401);
    const authorized = mcpRequest({ url: `${publicUrl}/mcp`, method: "tools/list" });
    authorized.headers.set("authorization", `Bearer ${await issuer.sign({}, "mcp")}`);
    assert.equal((await web.handler(authorized)).status, 200);
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
