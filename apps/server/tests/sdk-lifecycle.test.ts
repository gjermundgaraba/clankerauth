import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { it } from "@effect/vitest";
import { nodeHandler } from "../src/http/application.ts";
import { forwardClientId } from "../src/forward-auth/forward-auth.ts";
import { cookieJar, testIssuer } from "./test-issuer.ts";
import { listen } from "../src/platform/node-http.ts";
import { Effect, Layer, Schema } from "effect";
import { FetchHttpClient } from "effect/http";
import { Verifier } from "@gjermundgaraba/clankerauth-sdk";
import { Unauthorized } from "@gjermundgaraba/clankerauth-sdk/errors";
import { signOutUrl } from "@gjermundgaraba/clankerauth-sdk/session";

const owner = { email: "owner@example.internal", password: randomBytes(24).toString("base64url") };

const ApiKeyCreated = Schema.Struct({ key: Schema.String, keyId: Schema.String });

const startServer = Effect.gen(function* () {
  // why: no host, so `*.localhost` names reach it over either loopback family
  const listener = yield* listen(0);
  const url = `http://clankerauth.home.localhost:${listener.port}`;

  const services = yield* Layer.build(
    testIssuer({
      baseURL: url,
      port: listener.port,
      allowInsecureHttp: true,
      cookieDomain: "home.localhost",
    }),
  );

  yield* listener.serve(yield* nodeHandler().pipe(Effect.provideContext(services)));
  const cookies = cookieJar();

  const call = (
    path: string,
    body?: typeof Schema.Json.Type,
    headers: Record<string, string> = {},
  ) =>
    Effect.gen(function* () {
      const request = new Headers({ origin: url, cookie: cookies.header(), ...headers });

      if (body) request.set("content-type", "application/json");

      const response = yield* Effect.promise(() =>
        fetch(new URL(path, url), {
          method: body ? "POST" : "GET",
          redirect: "manual",
          headers: request,
          body: body ? JSON.stringify(body) : null,
        }),
      );

      cookies.keep(response);

      return response;
    });

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
        (yield* issuer.call("/api/putResource", {
          identifier: resource,
          name: "Notes",
          scopes: ["notes:read", "notes:write"],
        })).status,
        200,
      );

      const verifierFor = () =>
        Verifier.make({
          issuer: issuer.issuer,
          resource,
          store: Verifier.store(),
          requiredScopes: ["notes:read"],
        }).pipe(Effect.provide(FetchHttpClient.layer));

      const verifier = yield* verifierFor();

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
        store: Verifier.store(),
      }).pipe(Effect.provide(FetchHttpClient.layer));

      assert.ok((yield* Effect.flip(other.verifyToken(token))) instanceof Unauthorized);

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
      assert.ok((yield* Effect.flip(other.verifyToken(key))) instanceof Unauthorized);
      assert.equal(
        (yield* issuer.call("/api/updateApiKey", { keyId, enabled: false })).status,
        200,
      );
      // why: a verifier keeps the key list it read, so only a fresh one sees the disabled key
      yield* verifier.verifyToken(key);
      assert.ok(
        (yield* Effect.flip((yield* verifierFor()).verifyToken(key))) instanceof Unauthorized,
      );

      // why: Node's fetch is not a navigation, so forward auth answers 401, not a login redirect
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
