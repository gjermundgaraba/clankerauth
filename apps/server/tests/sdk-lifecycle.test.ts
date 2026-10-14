/** The package against the real server: forward-auth tokens, verification, API keys, logout. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { type IncomingMessage, type ServerResponse } from "node:http";
import { it } from "@effect/vitest";
import { nodeHandler } from "../src/http/application.ts";
import { forwardClientId } from "../src/forward-auth/forward-auth.ts";
import { testIssuer } from "./test-issuer.ts";
import { createNodeServer } from "../src/platform/node-http.ts";
import { Effect, Layer, Schema } from "effect";
import { FetchHttpClient } from "effect/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import { Unauthorized } from "@gjermundgaraba/clankerauth-sdk/errors";
import { signOutUrl } from "@gjermundgaraba/clankerauth-sdk/session";

const owner = { email: "owner@example.internal", password: randomBytes(24).toString("base64url") };

const ApiKeyCreated = Schema.Struct({ key: Schema.String, keyId: Schema.String });

const startServer = Effect.gen(function* () {
  let serve = (_incoming: IncomingMessage, outgoing: ServerResponse) => {
    outgoing.writeHead(503).end();
  };

  const server = createNodeServer((incoming, outgoing) => {
    serve(incoming, outgoing);
  });

  // Every interface: `*.localhost` names resolve to either loopback family.
  yield* Effect.acquireRelease(
    Effect.callback<void>((resume) => {
      server.listen(0, () => resume(Effect.void));
    }),
    () =>
      Effect.callback<void>((resume) => {
        server.closeAllConnections();
        server.close(() => resume(Effect.void));
      }),
  );
  const address = server.address();

  if (address === null || !(address instanceof Object) || !("port" in address))
    return yield* Effect.die(new Error("Expected TCP listener"));
  const { port } = address;
  // Forward auth shares one cookie domain between the issuer and the apps behind the proxy.
  const url = `http://clankerauth.home.localhost:${port}`;

  const services = yield* Layer.build(
    testIssuer({
      baseURL: url,
      port,
      allowInsecureHttp: true,
      cookieDomain: "home.localhost",
    }),
  );

  serve = yield* nodeHandler().pipe(Effect.provideContext(services));
  const cookies = new Map<string, string>();
  const cookieHeader = () => [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");

  const call = (
    path: string,
    body?: typeof Schema.Json.Type,
    headers: Record<string, string> = {},
  ) =>
    Effect.gen(function* () {
      const request = new Headers({ origin: url, cookie: cookieHeader(), ...headers });

      if (body) request.set("content-type", "application/json");

      const response = yield* Effect.promise(() =>
        fetch(new URL(path, url), {
          method: body ? "POST" : "GET",
          redirect: "manual",
          headers: request,
          body: body ? JSON.stringify(body) : undefined,
        }),
      );

      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(";")[0]!;
        cookies.set(pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1));
      }

      return response;
    });

  /** The proxy's subrequest for a browser request to `original` on an app behind it. */
  const forward = (resource: string, original: URL) =>
    call(`/forward-auth?resource=${encodeURIComponent(resource)}`, undefined, {
      "x-forwarded-proto": original.protocol.slice(0, -1),
      "x-forwarded-host": original.host,
      "x-forwarded-uri": `${original.pathname}${original.search}`,
    });

  return { url, issuer: `${url}/api/auth`, call, forward };
});

const text = (response: Response) => Effect.promise(() => response.text());

it.live(
  "forward-auth tokens and API keys verify with the SDK against the real issuer, until logout",
  () =>
    Effect.gen(function* () {
      const issuer = yield* startServer;
      const app = new URL("http://notes.home.localhost:7337/notes?x=1");
      const resource = `${app.origin}/api`;

      assert.equal((yield* issuer.call("/api/setupOwner", owner)).status, 201);
      assert.equal((yield* issuer.call("/api/auth/sign-in/email", owner)).status, 200);

      assert.equal(
        (yield* issuer.call("/api/createResource", {
          identifier: resource,
          name: "Notes",
          scopes: ["notes:read", "notes:write"],
        })).status,
        201,
      );

      const verifierFor = () =>
        Verifier.make({ issuer: issuer.issuer, resource, requiredScopes: ["notes:read"] }).pipe(
          Effect.provide(FetchHttpClient.layer),
        );

      const verifier = yield* verifierFor();

      // After login the owner continues to the app, which sets the forward cookie; the proxy's
      // subrequest then yields a token the verifier accepts for this resource only.
      const proceed = yield* issuer.call(
        `/forward-auth/continue?rd=${encodeURIComponent(app.href)}`,
      );

      assert.equal(proceed.status, 302, yield* text(proceed));
      assert.equal(proceed.headers.get("location"), app.href);
      const forwarded = yield* issuer.forward(resource, app);
      assert.equal(forwarded.status, 204, yield* text(forwarded));
      const authorization = forwarded.headers.get("authorization") ?? "";
      const token = authorization.slice("Bearer ".length);
      const principal = yield* verifier.verifyToken(token);
      assert.deepEqual(principal.scopes, ["notes:read", "notes:write"]);
      assert.deepEqual(principal.actor, { kind: "client", clientId: forwardClientId });

      const other = yield* Verifier.make({
        issuer: issuer.issuer,
        resource: `${app.origin}/mcp`,
      }).pipe(Effect.provide(FetchHttpClient.layer));

      assert.ok((yield* Effect.flip(other.verifyToken(token))) instanceof Unauthorized);

      // API keys verify offline, from the resource's key list, with their granted scopes and
      // the key as actor.
      const created = yield* issuer.call("/api/createApiKey", {
        name: "Backup script",
        permissions: { [resource]: ["notes:read"] },
        expiresAt: null,
      });

      assert.equal(created.status, 201, yield* text(created.clone()));

      const { key, keyId } = Schema.decodeUnknownSync(ApiKeyCreated)(
        yield* Effect.promise(() => created.json()),
      );

      const machine = yield* verifier.verifyToken(key);
      assert.equal(machine.subject, principal.subject);
      assert.deepEqual(machine.scopes, ["notes:read"]);
      assert.deepEqual(machine.actor, { kind: "key", keyId });
      // A key with no grant on that resource is not that resource's credential at all.
      assert.ok((yield* Effect.flip(other.verifyToken(key))) instanceof Unauthorized);
      assert.equal(
        (yield* issuer.call("/api/updateApiKey", { keyId, enabled: false })).status,
        200,
      );
      // A disabled key is gone from the next list: a verifier holding this minute's list
      // still accepts it, and one that reads the list now does not.
      yield* verifier.verifyToken(key);
      assert.ok(
        (yield* Effect.flip((yield* verifierFor()).verifyToken(key))) instanceof Unauthorized,
      );

      // Logout ends the issuer session. Node's fetch is a script's request, not a navigation,
      // so the next check is refused in place, and continuing asks for login.
      const logout = yield* issuer.call(signOutUrl(issuer.url, app.href));
      assert.equal(logout.status, 302);
      assert.equal(logout.headers.get("location"), app.href);
      assert.equal((yield* issuer.forward(resource, app)).status, 401);
      const login = yield* issuer.call(`/forward-auth/continue?rd=${encodeURIComponent(app.href)}`);
      assert.equal(login.status, 302);
      const target = new URL(login.headers.get("location") ?? "");
      assert.equal(`${target.origin}${target.pathname}`, `${issuer.url}/login`);
    }),
);
