import { randomBytes } from "node:crypto";
import { Redacted } from "effect";
import type { Settings } from "../src/config.ts";

/** Validated-shape settings for tests; the port follows the base URL unless overridden. */
export const testSettings = (
  overrides: Partial<Settings> & Pick<Settings, "baseURL" | "database">,
): Settings => ({
  secret: Redacted.make(randomBytes(32).toString("hex")),
  host: "127.0.0.1",
  port: Number(new URL(overrides.baseURL).port) || 3000,
  trustProxy: false,
  allowInsecureHttp: false,
  ...overrides,
});
