import { ConfigProvider, Effect, Redacted } from "effect";
import { expect, test } from "vite-plus/test";
import { loadSettings } from "../src/config.ts";

const baseURL = "https://clankerauth.example.test";

const secret = "test-only-secret-with-at-least-32-characters";

const load = (env: Record<string, string> = {}) =>
  Effect.runPromise(
    loadSettings.pipe(
      Effect.provide(
        ConfigProvider.layer(
          ConfigProvider.fromEnv({
            env: { CLANKERAUTH_BASE_URL: baseURL, CLANKERAUTH_BETTER_AUTH_SECRET: secret, ...env },
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
    database: "data/clankerauth.sqlite",
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
    (await load({ CLANKERAUTH_MCP_ALLOWED_ORIGINS: ` ${origins.join(", ")} ` })).mcpAllowedOrigins,
  ).toEqual(origins);
  expect((await load({ CLANKERAUTH_MCP_ALLOWED_ORIGINS: "" })).mcpAllowedOrigins).toEqual([]);
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
  rejects({ CLANKERAUTH_MCP_ALLOWED_ORIGINS: origins }, "CLANKERAUTH_MCP_ALLOWED_ORIGINS"),
);

test("proxy trust and plain HTTP are opt-in", async () => {
  const enabled = await load({
    CLANKERAUTH_TRUST_PROXY: "true",
    CLANKERAUTH_ALLOW_INSECURE_HTTP: "true",
  });

  expect(enabled.trustProxy).toBe(true);
  expect(enabled.allowInsecureHttp).toBe(true);
  await rejects({ CLANKERAUTH_BASE_URL: "http://clankerauth.internal" }, "CLANKERAUTH_BASE_URL");

  // The same flag governs the issuer origin and the MCP browser origins.
  const insecure = await load({
    CLANKERAUTH_BASE_URL: "http://clankerauth.internal",
    CLANKERAUTH_ALLOW_INSECURE_HTTP: "true",
    CLANKERAUTH_MCP_ALLOWED_ORIGINS: "http://client.internal",
  });

  expect(insecure.baseURL).toBe("http://clankerauth.internal");
  expect(insecure.mcpAllowedOrigins).toEqual(["http://client.internal"]);
  await rejects(
    { CLANKERAUTH_MCP_ALLOWED_ORIGINS: "http://client.internal" },
    "CLANKERAUTH_MCP_ALLOWED_ORIGINS",
  );
});

test("the cookie domain is optional and must be a bare parent domain of the issuer host", async () => {
  expect((await load({ CLANKERAUTH_COOKIE_DOMAIN: "example.test" })).cookieDomain).toBe(
    "example.test",
  );
  expect((await load({ CLANKERAUTH_COOKIE_DOMAIN: "clankerauth.example.test" })).cookieDomain).toBe(
    "clankerauth.example.test",
  );

  for (const cookieDomain of ["other.test", "test", ".example.test", "127.0.0.1"])
    await rejects({ CLANKERAUTH_COOKIE_DOMAIN: cookieDomain }, "CLANKERAUTH_COOKIE_DOMAIN");
});

test("the issuer origin, the secret and the port are validated as configuration", async () => {
  for (const url of [
    "http://clankerauth.internal",
    "https://clankerauth.internal/",
    "https://clankerauth.internal/path",
    "https://user:pass@clankerauth.internal",
    "not a URL",
  ])
    await rejects({ CLANKERAUTH_BASE_URL: url }, "CLANKERAUTH_BASE_URL");
  expect((await load({ CLANKERAUTH_BASE_URL: "https://clankerauth.internal" })).baseURL).toBe(
    "https://clankerauth.internal",
  );
  await rejects(
    { CLANKERAUTH_BETTER_AUTH_SECRET: "too short to sign anything" },
    "CLANKERAUTH_BETTER_AUTH_SECRET",
  );

  for (const port of ["0", "65536", "8080.5", "not a number"])
    await rejects({ CLANKERAUTH_PORT: port }, "PORT");
  expect((await load({ CLANKERAUTH_PORT: "8080" })).port).toBe(8080);
});
