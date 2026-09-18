import { Config, Effect, Redacted } from "effect";

export interface Settings {
  baseURL: string;
  secret: string;
  database: string;
  host: string;
  port: number;
  /** Additional browser origins allowed to call MCP with OAuth bearer tokens. */
  mcpAllowedOrigins?: readonly string[];
}

export const loadSettings = Effect.gen(function* () {
  const baseURL = yield* Config.String("AUTH_BASE_URL");
  const secret = Redacted.value(yield* Config.Redacted("BETTER_AUTH_SECRET"));

  const database = yield* Config.String("AUTH_DATABASE").pipe(
    Config.withDefault("data/auth.sqlite"),
  );

  const host = yield* Config.String("HOST").pipe(Config.withDefault("127.0.0.1"));
  const port = yield* Config.Number("PORT").pipe(Config.withDefault(3000));
  const origins = yield* Config.String("MCP_ALLOWED_ORIGINS").pipe(Config.withDefault(""));
  const mcpAllowedOrigins = origins.trim() ? origins.split(",").map((origin) => origin.trim()) : [];

  return yield* Effect.try(() =>
    validateSettings({ baseURL, secret, database, host, port, mcpAllowedOrigins }),
  );
});

const validOrigin = (value: string) => {
  try {
    const url = new URL(value);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);

    return (
      url.origin === value &&
      !url.username &&
      !url.password &&
      (url.protocol === "https:" || (url.protocol === "http:" && loopback))
    );
  } catch {
    return false;
  }
};

export function validateSettings(settings: Settings): Settings {
  if (!validOrigin(settings.baseURL))
    throw new Error("AUTH_BASE_URL must be an HTTPS origin (HTTP allowed only on loopback)");

  if (settings.secret.length < 32)
    throw new Error("BETTER_AUTH_SECRET must have at least 32 characters");

  if (!Number.isInteger(settings.port) || settings.port < 1 || settings.port > 65535)
    throw new Error("Invalid PORT");
  const mcpAllowedOrigins = [...new Set(settings.mcpAllowedOrigins ?? [])];

  if (!mcpAllowedOrigins.every(validOrigin))
    throw new Error(
      "MCP_ALLOWED_ORIGINS must contain exact HTTPS origins (HTTP allowed only on loopback)",
    );

  return { ...settings, mcpAllowedOrigins };
}
