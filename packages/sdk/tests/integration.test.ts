import assert from "node:assert/strict";

import { expect, it } from "@effect/vitest";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import * as Authentication from "@gjermundgaraba/effect-actions/Authentication";
import * as Testing from "@gjermundgaraba/effect-actions/Testing";
import { Effect, Layer, Logger, Result, Schema } from "effect";
import {
  FetchHttpClient,
  HttpClient,
  HttpClientRequest,
  HttpRouter,
  HttpServer,
  HttpServerResponse,
} from "effect/http";

import { Resource } from "../src/effect-actions.ts";
import { ProviderUnavailable } from "../src/errors.ts";
import { Verifier } from "../src/index.ts";
import { CurrentPrincipal, Whoami } from "../src/session.ts";
import {
  authorize,
  fakeIssuer,
  json,
  Login,
  Notes,
  publicUrl,
  sent,
  startIssuer,
  webHandler,
} from "./support.ts";

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

const Http = ActionHttp.make([Identity, Write, Whoami], {
  authentication: Login,
});

const identity = Effect.map(CurrentPrincipal, ({ actor }) => {
  if (actor.kind === "key") {
    return actor.keyId;
  }

  if (actor.kind === "client") {
    return actor.clientId;
  }

  return "local";
});

const authorizationHeaders = (
  authorization: string | undefined
): Record<string, string> =>
  authorization === undefined ? {} : { authorization };

const seen = (response: Response) =>
  Effect.map(json(response), (body) => ({
    status: response.status,
    challenge: response.headers.get("www-authenticate"),
    body,
  }));

it.live(
  "one resource protects HTTP and MCP, and the application's one rule authorizes both",
  () =>
    Effect.gen(function* () {
      const issuer = yield* startIssuer(resourceId);

      const app = Action.implement(
        [Identity, Write],
        { identity: () => identity, write: () => Effect.succeed("written") },
        { authorize }
      );

      const web = yield* webHandler(() =>
        HttpRouter.toWebHandler(
          Layer.mergeAll(
            ActionHttp.layer(Http, [app, Notes.session]),
            ActionMcp.layerHttp(app, {
              name: "notes",
              version: "1.0.0",
              authentication: Login,
            })
          ).pipe(
            Layer.provide(Notes.provider),
            Layer.provide(
              Notes.layer({
                issuer: issuer.issuer,
                publicUrl: new URL(publicUrl),
                store: Verifier.store(),
              })
            ),
            Layer.provide(FetchHttpClient.layer),
            Layer.provide(HttpServer.layerServices)
          )
        )
      );

      const call = (name: string, token?: string) => {
        const headers = new Headers({ "content-type": "application/json" });

        if (token !== undefined && token !== "") {
          headers.set("authorization", `Bearer ${token}`);
        }

        return Effect.promise(
          async () =>
            await web.handler(
              new Request(`${publicUrl}/api/${name}`, {
                method: "POST",
                headers,
                body: "{}",
              })
            )
        );
      };

      const missing = yield* call("identity");
      assert.equal(missing.status, 401);
      assert.match(
        missing.headers.get("www-authenticate") ?? "",
        /scope="notes:read"/u
      );

      const identities = yield* Effect.forEach(
        [issuer.key, issuer.readOnlyKey],
        (token) => Effect.flatMap(call("identity", token), json),
        { concurrency: "unbounded" }
      );

      assert.deepEqual(identities, ["key-1", "key-2"]);
      assert.equal(yield* json(yield* call("write", issuer.key)), "written");

      assert.deepEqual(yield* json(yield* call("whoami", issuer.readOnlyKey)), {
        subject: "owner",
        issuer: issuer.issuer,
        scopes: ["notes:read"],
      });

      const refused = yield* call("write", issuer.readOnlyKey);
      assert.equal(refused.status, 403);
      assert.deepEqual(
        yield* json(refused),
        sent(new Action.Forbidden({ message: "Requires notes:write." }))
      );

      const stepUp = yield* call(
        "write",
        yield* Effect.promise(
          async () => await issuer.sign({ scope: "notes:read" })
        )
      );

      assert.equal(stepUp.status, 403);
      assert.deepEqual(
        yield* json(stepUp),
        sent(
          new Action.Forbidden({
            message: "Requires notes:write.",
            scopes: ["notes:write"],
          })
        )
      );

      const metadata = yield* Effect.promise(
        async () =>
          await web.handler(
            new Request(`${publicUrl}/.well-known/oauth-protected-resource`)
          )
      );

      assert.equal(metadata.status, 200);

      expect(yield* json(metadata)).toMatchObject({
        resource: resourceId,
        authorization_servers: [issuer.issuer],
        scopes_supported: ["notes:read", "notes:write"],
      });

      const mcp = (headers: Record<string, string>) =>
        Effect.promise(
          async () =>
            await web.handler(
              Result.getOrThrow(
                HttpClientRequest.toWebResult(
                  ActionMcp.request("tools/list", undefined, {
                    url: `${publicUrl}/mcp`,
                    headers,
                  })
                )
              )
            )
        );

      assert.equal(
        (yield* mcp({
          authorization: `Bearer ${yield* Effect.promise(async () => await issuer.sign())}`,
        })).status,
        200
      );

      const asKey = HttpClient.mapRequest(
        HttpClientRequest.bearerToken(issuer.readOnlyKey)
      );

      const refusedTool = yield* Effect.gen(function* () {
        const tools = yield* ActionMcp.client(app.actions, {
          url: `${publicUrl}/mcp`,
          transformClient: asKey,
        });

        return yield* Effect.flip(tools.write());
      }).pipe(Effect.provide(Testing.layer(web.handler)));

      assert.ok(refusedTool instanceof Action.Forbidden);
      assert.equal(refusedTool.scopes, undefined);

      issuer.fail(503);
      assert.equal((yield* call("identity", issuer.key)).status, 200);
    })
);

it.live("a surface without discovery authenticates and publishes nothing", () =>
  Effect.gen(function* () {
    const issuer = yield* startIssuer(resourceId);

    const app = Action.implement(Identity, () => identity, { authorize });

    const web = yield* webHandler(() =>
      HttpRouter.toWebHandler(
        ActionHttp.layer(Http, app).pipe(
          Layer.provide(Notes.provider),
          Layer.provide(
            Notes.layer({
              issuer: issuer.issuer,
              publicUrl: new URL(publicUrl),
              store: Verifier.store(),

              discovery: false,
            })
          ),
          Layer.provide(FetchHttpClient.layer),
          Layer.provide(HttpServer.layerServices)
        )
      )
    );

    const call = (authorization?: string) => {
      const headers = new Headers({ "content-type": "application/json" });

      if (authorization !== undefined) {
        headers.set("authorization", authorization);
      }

      return Effect.promise(
        async () =>
          await web.handler(
            new Request(`${publicUrl}/api/identity`, {
              method: "POST",
              headers,
              body: "{}",
            })
          )
      );
    };

    assert.equal((yield* call(`Bearer ${issuer.key}`)).status, 200);

    const missing = yield* call();
    assert.equal(missing.status, 401);

    assert.equal(
      (yield* Effect.promise(
        async () =>
          await web.handler(
            new Request(`${publicUrl}/.well-known/oauth-protected-resource`)
          )
      )).status,
      404
    );
  })
);

it.live(
  "a listener publishing discovery warns once when reached at another host",
  () =>
    Effect.gen(function* () {
      const issuer = yield* startIssuer(resourceId);

      const app = Action.implement(Identity, () => identity, { authorize });

      const warnings: string[] = [];

      const capture = Logger.make(({ logLevel, message }) => {
        if (logLevel === "Warn") {
          warnings.push(String(message));
        }
      });

      const listener = (discovery: boolean) =>
        webHandler(() =>
          HttpRouter.toWebHandler(
            ActionHttp.layer(Http, app).pipe(
              Layer.provide(Notes.provider),
              Layer.provide(
                Notes.layer({
                  issuer: issuer.issuer,
                  publicUrl: new URL(publicUrl),
                  store: Verifier.store(),
                  discovery,
                })
              ),
              Layer.provide(FetchHttpClient.layer),
              Layer.provide(HttpServer.layerServices),
              Layer.provide(Logger.layer([capture]))
            )
          )
        );

      const call = (
        web: Effect.Success<ReturnType<typeof listener>>,
        host: string
      ) =>
        Effect.promise(
          async () =>
            await web.handler(
              new Request(`${publicUrl}/api/identity`, {
                method: "POST",
                headers: {
                  "content-type": "application/json",
                  host,
                  authorization: `Bearer ${issuer.key}`,
                },
                body: "{}",
              })
            )
        );

      const publishing = yield* listener(true);
      const beside = yield* listener(false);

      assert.equal(
        (yield* call(publishing, new URL(publicUrl).host)).status,
        200
      );
      assert.deepEqual(warnings, []);

      assert.equal(
        (yield* call(publishing, "notes.elsewhere.example")).status,
        200
      );
      assert.equal(
        (yield* call(publishing, "notes.elsewhere.example")).status,
        200
      );
      assert.equal(warnings.length, 1);
      assert.match(warnings[0] ?? "", /notes\.elsewhere\.example/u);

      assert.equal(
        (yield* call(beside, "notes.elsewhere.example")).status,
        200
      );
      assert.equal(warnings.length, 1);
    })
);

const Admin = Resource.make(
  Authentication.make("fixture.admin", CurrentPrincipal, {
    error: ProviderUnavailable,
  }),
  { scopes: ["notes:read", "notes:write"], required: "notes:read" }
);

const Machine = Resource.make(
  Authentication.make("fixture.machine", CurrentPrincipal, {
    error: ProviderUnavailable,
  }),
  { scopes: ["notes:machine"], required: "notes:machine" }
);

const AdminHttp = ActionHttp.make([Identity, Write, Whoami], {
  authentication: Admin.authentication,
});

const MachineHttp = ActionHttp.make([Identity], {
  prefix: "/machine",
  authentication: Machine.authentication,
});

const admin = Action.implement(
  [Identity, Write],
  { identity: () => identity, write: () => Effect.succeed("written") },
  {
    authorize: (action) =>
      action.readOnly ? Effect.void : Admin.requires("notes:write"),
  }
);

const machine = Action.implement(Identity, () => identity, {
  authorize: Action.allowAll,
});

it.live.each(["admin first", "machine first"] as const)(
  "two resources in one layer graph, without Layer.fresh, each guard their own surface, built %s",
  (order) =>
    Effect.gen(function* () {
      const issuer = yield* fakeIssuer({
        resource: resourceId,
        scopes: ["notes:read", "notes:write", "notes:machine"],
      });

      const options = {
        issuer: issuer.issuer,
        publicUrl: new URL(publicUrl),
        store: Verifier.store(),
      };

      const adminSurface = ActionHttp.layer(AdminHttp, [
        admin,
        Admin.session,
      ]).pipe(
        Layer.provide(Admin.provider),
        Layer.provide(Admin.layer(options))
      );

      const machineSurface = ActionHttp.layer(MachineHttp, machine).pipe(
        Layer.provide(Machine.provider),
        Layer.provide(Machine.layer({ ...options, discovery: false }))
      );

      const web = yield* webHandler(() =>
        HttpRouter.toWebHandler(
          (order === "admin first"
            ? Layer.mergeAll(adminSurface, machineSurface)
            : Layer.mergeAll(machineSurface, adminSurface)
          ).pipe(
            Layer.provide(FetchHttpClient.layer),
            Layer.provide(HttpServer.layerServices)
          )
        )
      );

      const call = (path: string, token: string) =>
        Effect.promise(
          async () =>
            await web.handler(
              new Request(`${publicUrl}${path}`, {
                method: "POST",
                headers: {
                  "content-type": "application/json",
                  authorization: `Bearer ${token}`,
                },
                body: "{}",
              })
            )
        );

      const reader = yield* Effect.promise(
        async () => await issuer.sign({ scope: "notes:read" })
      );

      const machineToken = yield* Effect.promise(
        async () => await issuer.sign({ scope: "notes:machine" })
      );

      assert.equal((yield* call("/api/identity", reader)).status, 200);
      assert.equal((yield* call("/api/identity", machineToken)).status, 403);
      assert.equal((yield* call("/api/write", reader)).status, 403);
      assert.equal((yield* call("/api/whoami", reader)).status, 200);
      assert.equal(
        (yield* call("/machine/identity", machineToken)).status,
        200
      );
      assert.equal((yield* call("/machine/identity", reader)).status, 403);

      const discovery = yield* Effect.promise(
        async () =>
          await web.handler(
            new Request(`${publicUrl}/.well-known/oauth-protected-resource`)
          )
      );

      assert.equal(discovery.status, 200);
      expect(yield* json(discovery)).toMatchObject({
        scopes_supported: ["notes:read", "notes:write"],
      });
    })
);

it.live(
  "admitted(scope) refuses a host's own route as the action requiring the scope is refused",
  () =>
    Effect.gen(function* () {
      const issuer = yield* startIssuer(resourceId);

      const app = Action.implement(
        [Identity, Write],
        { identity: () => identity, write: () => Effect.succeed("written") },
        { authorize }
      );

      const subject = Effect.map(CurrentPrincipal, (principal) =>
        HttpServerResponse.text(principal.subject)
      );

      const web = yield* webHandler(() =>
        HttpRouter.toWebHandler(
          Layer.mergeAll(
            ActionHttp.layer(Http, app),
            HttpRouter.add("PUT", "/upload", subject).pipe(
              Layer.provide(Notes.admitted("notes:write").layer)
            )
          ).pipe(
            Layer.provide(Notes.provider),
            Layer.provide(
              Notes.layer({
                issuer: issuer.issuer,
                publicUrl: new URL(publicUrl),
                store: Verifier.store(),
              })
            ),
            Layer.provide(FetchHttpClient.layer),
            Layer.provide(HttpServer.layerServices)
          )
        )
      );

      const write = (authorization?: string) =>
        Effect.promise(
          async () =>
            await web.handler(
              new Request(`${publicUrl}/api/write`, {
                method: "POST",
                headers: {
                  ...authorizationHeaders(authorization),
                  "content-type": "application/json",
                },
                body: "{}",
              })
            )
        );

      const upload = (authorization?: string) =>
        Effect.promise(
          async () =>
            await web.handler(
              new Request(`${publicUrl}/upload`, {
                method: "PUT",
                headers: authorizationHeaders(authorization),
              })
            )
        );

      const stepUpToken = yield* Effect.promise(
        async () => await issuer.sign({ scope: "notes:read" })
      );

      for (const authorization of [
        undefined,
        `Bearer ${issuer.readOnlyKey}`,
        `Bearer ${stepUpToken}`,
      ]) {
        const expected = yield* seen(yield* write(authorization));

        assert.notEqual(expected.status, 200);
        assert.deepEqual(
          yield* seen(yield* upload(authorization)),
          expected,
          `${authorization}`
        );
      }

      const written = yield* upload(`Bearer ${issuer.key}`);
      assert.equal(written.status, 200);
      assert.equal(
        yield* Effect.promise(async () => await written.text()),
        "owner"
      );
    })
);
