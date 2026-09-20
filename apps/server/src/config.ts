import { Config, Effect, Redacted } from "effect";

export interface Settings {
  baseURL: string;
  secret: Redacted.Redacted<string>;
  database: string;
  host: string;
  port: number;
  /** Additional browser origins allowed to call MCP with OAuth bearer tokens. */
  mcpAllowedOrigins?: readonly string[];
  /** Take the client address from the last X-Forwarded-For hop set by a trusted reverse proxy. */
  trustProxy: boolean;
  /** Permit a plain-HTTP issuer beyond loopback, for private networks without TLS. */
  allowInsecureHttp: boolean;
}

export const loadSettings = Effect.gen(function* () {
  const baseURL = yield* Config.String("AUTH_BASE_URL");
  const secret = yield* Config.Redacted("BETTER_AUTH_SECRET");

  const database = yield* Config.String("AUTH_DATABASE").pipe(
    Config.withDefault("data/auth.sqlite"),
  );

  const host = yield* Config.String("HOST").pipe(Config.withDefault("127.0.0.1"));
  const port = yield* Config.Number("PORT").pipe(Config.withDefault(3000));
  const origins = yield* Config.String("MCP_ALLOWED_ORIGINS").pipe(Config.withDefault(""));
  const mcpAllowedOrigins = origins.trim() ? origins.split(",").map((origin) => origin.trim()) : [];
  const trustProxy = yield* Config.Boolean("TRUST_PROXY").pipe(Config.withDefault(false));

  const allowInsecureHttp = yield* Config.Boolean("ALLOW_INSECURE_HTTP").pipe(
    Config.withDefault(false),
  );

  return yield* Effect.try(() =>
    validateSettings({
      baseURL,
      secret,
      database,
      host,
      port,
      mcpAllowedOrigins,
      trustProxy,
      allowInsecureHttp,
    }),
  );
});

const validOrigin = (value: string, allowInsecureHttp: boolean) => {
  try {
    const url = new URL(value);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);

    return (
      url.origin === value &&
      !url.username &&
      !url.password &&
      (url.protocol === "https:" || (url.protocol === "http:" && (loopback || allowInsecureHttp)))
    );
  } catch {
    return false;
  }
};

export function validateSettings(settings: Settings): Settings {
  const { allowInsecureHttp } = settings;

  if (!validOrigin(settings.baseURL, allowInsecureHttp))
    throw new Error(
      "AUTH_BASE_URL must be an HTTPS origin (HTTP allowed on loopback, or anywhere with ALLOW_INSECURE_HTTP=true)",
    );

  if (Redacted.value(settings.secret).length < 32)
    throw new Error("BETTER_AUTH_SECRET must have at least 32 characters");

  if (!Number.isInteger(settings.port) || settings.port < 1 || settings.port > 65535)
    throw new Error("Invalid PORT");
  const mcpAllowedOrigins = [...new Set(settings.mcpAllowedOrigins ?? [])];

  if (!mcpAllowedOrigins.every((origin) => validOrigin(origin, allowInsecureHttp)))
    throw new Error(
      "MCP_ALLOWED_ORIGINS must contain exact HTTPS origins (HTTP allowed on loopback, or anywhere with ALLOW_INSECURE_HTTP=true)",
    );

  return { ...settings, mcpAllowedOrigins };
}
