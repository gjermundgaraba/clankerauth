import { ConfigProvider, Effect, Redacted } from "effect";
import { expect, test } from "vite-plus/test";
import { loadSettings } from "../src/config.ts";

const baseURL = "https://auth.example.test";

const secret = "test-only-secret-with-at-least-32-characters";

const load = (env: Record<string, string> = {}) =>
  Effect.runPromise(
    loadSettings.pipe(
      Effect.provide(
        ConfigProvider.layer(
          ConfigProvider.fromEnv({
            env: { AUTH_BASE_URL: baseURL, BETTER_AUTH_SECRET: secret, ...env },
          }),
        ),
      ),
    ),
  );

/** Every rejection names the variable that failed. */
const rejects = async (env: Record<string, string>, variable: string) => {
  await expect(load(env), JSON.stringify(env)).rejects.toThrow(variable);
};

test("an environment with only the two required variables is a complete configuration", async () => {
  expect(await load()).toEqual({
    baseURL,
    secret: Redacted.make(secret),
    database: "data/auth.sqlite",
    host: "127.0.0.1",
    port: 3000,
    mcpAllowedOrigins: [],
    trustProxy: false,
    allowInsecureHttp: false,
    cookieDomain: undefined,
  });
});

test("MCP browser origins are trimmed, and empty when unset", async () => {
  const origins = [
    "https://client.example.test",
    "http://localhost:9876",
    "http://127.0.0.1:9876",
    "http://[::1]:9876",
  ];

  expect(
    (await load({ MCP_ALLOWED_ORIGINS: ` ${origins.join(", ")} ` })).mcpAllowedOrigins,
  ).toEqual(origins);
  expect((await load({ MCP_ALLOWED_ORIGINS: "" })).mcpAllowedOrigins).toEqual([]);
});

test.each([
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
  rejects({ MCP_ALLOWED_ORIGINS: origins }, "MCP_ALLOWED_ORIGINS"),
);

test("proxy trust and plain HTTP are opt-in", async () => {
  const enabled = await load({ TRUST_PROXY: "true", ALLOW_INSECURE_HTTP: "true" });
  expect(enabled.trustProxy).toBe(true);
  expect(enabled.allowInsecureHttp).toBe(true);
  await rejects({ AUTH_BASE_URL: "http://auth.internal" }, "AUTH_BASE_URL");

  // The same flag governs the issuer origin and the MCP browser origins.
  const insecure = await load({
    AUTH_BASE_URL: "http://auth.internal",
    ALLOW_INSECURE_HTTP: "true",
    MCP_ALLOWED_ORIGINS: "http://client.internal",
  });

  expect(insecure.baseURL).toBe("http://auth.internal");
  expect(insecure.mcpAllowedOrigins).toEqual(["http://client.internal"]);
  await rejects({ MCP_ALLOWED_ORIGINS: "http://client.internal" }, "MCP_ALLOWED_ORIGINS");
});

test("the cookie domain is optional and must be a bare parent domain of the issuer host", async () => {
  expect((await load({ AUTH_COOKIE_DOMAIN: "example.test" })).cookieDomain).toBe("example.test");
  expect((await load({ AUTH_COOKIE_DOMAIN: "auth.example.test" })).cookieDomain).toBe(
    "auth.example.test",
  );

  for (const cookieDomain of ["other.test", "test", ".example.test", "127.0.0.1"])
    await rejects({ AUTH_COOKIE_DOMAIN: cookieDomain }, "AUTH_COOKIE_DOMAIN");
});

test("the issuer origin, the secret and the port are validated as configuration", async () => {
  for (const url of [
    "http://auth.internal",
    "https://auth.internal/",
    "https://auth.internal/path",
    "https://user:pass@auth.internal",
    "not a URL",
  ])
    await rejects({ AUTH_BASE_URL: url }, "AUTH_BASE_URL");
  expect((await load({ AUTH_BASE_URL: "https://auth.internal" })).baseURL).toBe(
    "https://auth.internal",
  );
  await rejects({ BETTER_AUTH_SECRET: "too short to sign anything" }, "BETTER_AUTH_SECRET");

  for (const port of ["0", "65536", "8080.5", "not a number"])
    await rejects({ PORT: port }, "PORT");
  expect((await load({ PORT: "8080" })).port).toBe(8080);
});
