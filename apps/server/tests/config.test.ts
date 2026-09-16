import { ConfigProvider, Effect } from "effect";
import { expect, test } from "vite-plus/test";
import { loadSettings, validateSettings } from "../src/config.ts";

const settings = {
  baseURL: "https://auth.example.test",
  secret: "test-only-secret-with-at-least-32-characters",
  database: ":memory:",
  host: "127.0.0.1",
  port: 3000,
};
const load = (origins?: string) =>
  Effect.runPromise(
    loadSettings.pipe(
      Effect.provide(
        ConfigProvider.layer(
          ConfigProvider.fromUnknown({
            AUTH_BASE_URL: settings.baseURL,
            BETTER_AUTH_SECRET: settings.secret,
            ...(origins === undefined ? {} : { MCP_ALLOWED_ORIGINS: origins }),
          }),
        ),
      ),
    ),
  );

test("MCP browser origins default to no additional origins", async () => {
  expect(validateSettings(settings).mcpAllowedOrigins).toEqual([]);
  expect((await load()).mcpAllowedOrigins).toEqual([]);
  expect((await load("  ")).mcpAllowedOrigins).toEqual([]);
});

test("MCP browser origins accept exact HTTPS and loopback origins and deduplicate", async () => {
  const origins = [
    "https://client.example.test",
    "http://localhost:9876",
    "http://127.0.0.1:9876",
    "http://[::1]:9876",
  ];
  expect(
    validateSettings({
      ...settings,
      mcpAllowedOrigins: [...origins, "https://client.example.test"],
    }).mcpAllowedOrigins,
  ).toEqual(origins);
  expect((await load(` ${origins.join(", ")}, ${origins[0]} `)).mcpAllowedOrigins).toEqual(origins);
});

test.each([
  "*",
  "null",
  "",
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
])("MCP browser configuration rejects non-origin value %j", (origin) => {
  expect(() => validateSettings({ ...settings, mcpAllowedOrigins: [origin] })).toThrow(
    "MCP_ALLOWED_ORIGINS",
  );
});

test("MCP browser environment configuration rejects empty entries and invalid origins", async () => {
  for (const origins of [
    "https://client.example.test,",
    ",https://client.example.test",
    "https://client.example.test, ,https://other.example.test",
    "https://client.example.test, *",
  ]) {
    await expect(load(origins)).rejects.toThrow();
  }
});
