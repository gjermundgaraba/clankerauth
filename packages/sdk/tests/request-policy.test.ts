import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { HttpRouter, HttpServer, HttpServerResponse } from "effect/unstable/http";
import { RequestPolicy } from "../src/index.ts";

const publicUrl = new URL("https://notes.example");

const policy = RequestPolicy.make({
  publicUrl,
  allowedOrigins: ["wtf://app"],
  exemptPaths: ["/healthz"],
});

const allows = (target: string, host: string | undefined, origin?: string): boolean =>
  policy.allows({ target, host, origin });

test("the Host header must equal the public host, as sent", () => {
  assert.equal(allows("/api", "notes.example"), true);
  assert.equal(allows("/api", "other.example"), false);
  // A forwarded header cannot redefine the app's identity, and no normalization widens it.
  assert.equal(allows("/api", "notes.example:443"), false);
  assert.equal(allows("/api", "NOTES.EXAMPLE"), false);
  assert.equal(allows("/api", undefined), false);
  assert.equal(allows("/api", ""), false);
});

test("a port is part of the host, so a development origin is exact too", () => {
  const local = RequestPolicy.make({ publicUrl: new URL("http://app.notes.localhost:5173") });
  assert.equal(
    local.allows({ target: "/", host: "app.notes.localhost:5173", origin: undefined }),
    true,
  );
  assert.equal(
    local.allows({ target: "/", host: "app.notes.localhost", origin: undefined }),
    false,
  );
  assert.equal(
    local.allows({ target: "/", host: "app.notes.localhost:5174", origin: undefined }),
    false,
  );
});

test("an Origin is optional, but when sent must be the public one or explicitly allowed", () => {
  assert.equal(allows("/api", "notes.example", undefined), true);
  assert.equal(allows("/api", "notes.example", "https://notes.example"), true);
  assert.equal(allows("/api", "notes.example", "wtf://app"), true);
  assert.equal(allows("/api", "notes.example", "https://evil.example"), false);
  assert.equal(allows("/api", "notes.example", "https://notes.example.evil"), false);
  assert.equal(allows("/api", "notes.example", "null"), false);
  assert.equal(allows("/api", "notes.example", "https://notes.example/"), false);
});

test("exempt paths answer without either header, and match exactly", () => {
  assert.equal(allows("/healthz", undefined), true);
  assert.equal(allows("/healthz?probe=1", undefined), true);
  assert.equal(allows("/healthz#fragment", undefined), true);
  assert.equal(allows("https://anything.example/healthz", undefined), true);
  assert.equal(allows("/healthz/deep", undefined), false);
  assert.equal(allows("/healthzz", undefined), false);
  assert.equal(allows("/health", undefined), false);
  assert.equal(allows("/", undefined), false);
});

test("a malformed target is a path, never a parse failure", () => {
  for (const target of ["", "//", "://", "http://", "%%%", "/a%2", "\\\\evil", "http://h"]) {
    assert.doesNotThrow(() => policy.allows({ target, host: "notes.example", origin: undefined }));
  }

  assert.equal(allows("", "notes.example"), true);
  assert.equal(allows("http://h", "notes.example"), true);
});

test("the middleware refuses before any handler runs and lets exempt paths through", async () => {
  let handled = 0;

  const routes = Layer.mergeAll(
    HttpRouter.add(
      "GET",
      "/api",
      Effect.sync(() => {
        handled++;

        return HttpServerResponse.text("api");
      }),
    ),
    HttpRouter.add("GET", "/healthz", Effect.succeed(HttpServerResponse.text("ok"))),
  ).pipe(Layer.provide(policy.middleware.layer));

  const web = HttpRouter.toWebHandler(routes.pipe(Layer.provide(HttpServer.layerServices)), {
    disableLogger: true,
  });

  const call = (path: string, headers: Record<string, string>) =>
    web.handler(new Request(`https://notes.example${path}`, { headers }));

  try {
    assert.equal((await call("/api", { host: "notes.example" })).status, 200);
    assert.equal(handled, 1);

    const refused = await call("/api", { host: "notes.example.evil" });
    assert.equal(refused.status, 403);
    assert.equal(await refused.text(), "Forbidden");
    assert.equal(handled, 1);

    assert.equal(
      (await call("/api", { host: "notes.example", origin: "https://evil.example" })).status,
      403,
    );
    assert.equal(handled, 1);

    assert.equal((await call("/api", { host: "notes.example", origin: "wtf://app" })).status, 200);
    assert.equal(handled, 2);

    // A container probe carries neither header.
    assert.equal((await call("/healthz", {})).status, 200);
  } finally {
    await web.dispose();
  }
});
