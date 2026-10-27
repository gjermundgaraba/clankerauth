import { it } from "@effect/vitest";
import { ConfigProvider, Effect, Redacted } from "effect";
import { expect } from "vite-plus/test";

import { loadSettings } from "../../src/issuer/settings.ts";

const baseURL = "https://clankerauth.example.test";

const secret = "test-only-secret-with-at-least-32-characters";

const load = (env: Record<string, string> = {}) =>
  loadSettings.pipe(
    Effect.provide(
      ConfigProvider.layer(
        ConfigProvider.fromEnv({
          env: {
            CLANKERAUTH_BASE_URL: baseURL,
            CLANKERAUTH_BETTER_AUTH_SECRET: secret,
            ...env,
          },
        })
      )
    )
  );

const rejects = (env: Record<string, string>, variable: string) =>
  Effect.gen(function* () {
    expect(
      (yield* Effect.flip(load(env))).message,
      JSON.stringify(env)
    ).toContain(variable);
  });

it.effect(
  "an environment with only the two required variables is a complete configuration",
  () =>
    Effect.gen(function* () {
      expect(yield* load()).toStrictEqual({
        baseURL,
        secret: Redacted.make(secret),
        database: "data/clankerauth.sqlite",
        host: "127.0.0.1",
        port: 3000,
        mcpAllowedOrigins: [],
        trustProxy: false,
        allowInsecureHttp: false,
        cookieDomain: undefined,
      });
    })
);

it.effect("MCP browser origins are trimmed, and empty when unset", () =>
  Effect.gen(function* () {
    const origins = [
      "https://client.example.test",
      "http://localhost:9876",
      "http://127.0.0.1:9876",
      "http://[::1]:9876",
    ];

    expect(
      (yield* load({
        CLANKERAUTH_MCP_ALLOWED_ORIGINS: ` ${origins.join(", ")} `,
      })).mcpAllowedOrigins
    ).toStrictEqual(origins);
    expect(
      (yield* load({ CLANKERAUTH_MCP_ALLOWED_ORIGINS: "" })).mcpAllowedOrigins
    ).toStrictEqual([]);
  })
);

it.effect.each([
  "*",
  "null",
  "   ",
  "http://client.example.test",
  "http://localhost.example.test",
  "https://client.example.test/",
  "https://client.example.test/path",
  "https://client.example.test?query=value",
  "https://client.example.test#fragment",
  "https://user:password@client.example.test",
  "https://CLIENT.example.test",
  "https://client.example.test:443",
  "file:///tmp/client",
  "https://client.example.test,",
  ",https://client.example.test",
  "https://client.example.test, ,https://other.example.test",
  "https://client.example.test, *",
])("MCP browser configuration rejects non-origin value %j", (origins) =>
  rejects(
    { CLANKERAUTH_MCP_ALLOWED_ORIGINS: origins },
    "CLANKERAUTH_MCP_ALLOWED_ORIGINS"
  )
);

it.effect("proxy trust and plain HTTP are opt-in", () =>
  Effect.gen(function* () {
    const enabled = yield* load({
      CLANKERAUTH_TRUST_PROXY: "true",
      CLANKERAUTH_ALLOW_INSECURE_HTTP: "true",
    });

    expect(enabled.trustProxy).toBe(true);
    expect(enabled.allowInsecureHttp).toBe(true);
    yield* rejects(
      { CLANKERAUTH_BASE_URL: "http://clankerauth.internal" },
      "CLANKERAUTH_BASE_URL"
    );

    const insecure = yield* load({
      CLANKERAUTH_BASE_URL: "http://clankerauth.internal",
      CLANKERAUTH_ALLOW_INSECURE_HTTP: "true",
      CLANKERAUTH_MCP_ALLOWED_ORIGINS: "http://client.internal",
    });

    expect(insecure.baseURL).toBe("http://clankerauth.internal");
    expect(insecure.mcpAllowedOrigins).toStrictEqual([
      "http://client.internal",
    ]);
    yield* rejects(
      { CLANKERAUTH_MCP_ALLOWED_ORIGINS: "http://client.internal" },
      "CLANKERAUTH_MCP_ALLOWED_ORIGINS"
    );
  })
);

it.effect(
  "the cookie domain is optional and must be a bare parent domain of the issuer host",
  () =>
    Effect.gen(function* () {
      expect(
        (yield* load({ CLANKERAUTH_COOKIE_DOMAIN: "example.test" }))
          .cookieDomain
      ).toBe("example.test");
      expect(
        (yield* load({ CLANKERAUTH_COOKIE_DOMAIN: "clankerauth.example.test" }))
          .cookieDomain
      ).toBe("clankerauth.example.test");

      for (const cookieDomain of [
        "other.test",
        "test",
        ".example.test",
        "127.0.0.1",
      ]) {
        yield* rejects(
          { CLANKERAUTH_COOKIE_DOMAIN: cookieDomain },
          "CLANKERAUTH_COOKIE_DOMAIN"
        );
      }
    })
);

it.effect(
  "the issuer origin, the secret and the port are validated as configuration",
  () =>
    Effect.gen(function* () {
      for (const url of [
        "http://clankerauth.internal",
        "https://clankerauth.internal/",
        "https://clankerauth.internal/path",
        "https://user:pass@clankerauth.internal",
        "not a URL",
      ]) {
        yield* rejects({ CLANKERAUTH_BASE_URL: url }, "CLANKERAUTH_BASE_URL");
      }

      expect(
        (yield* load({ CLANKERAUTH_BASE_URL: "https://clankerauth.internal" }))
          .baseURL
      ).toBe("https://clankerauth.internal");
      yield* rejects(
        { CLANKERAUTH_BETTER_AUTH_SECRET: "too short to sign anything" },
        "CLANKERAUTH_BETTER_AUTH_SECRET"
      );

      for (const port of ["0", "65536", "8080.5", "not a number"]) {
        yield* rejects({ CLANKERAUTH_PORT: port }, "PORT");
      }

      expect((yield* load({ CLANKERAUTH_PORT: "8080" })).port).toBe(8080);
    })
);
