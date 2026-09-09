import { Config, Effect, Redacted } from "effect";

export interface Settings {
  baseURL: string;
  secret: string;
  database: string;
  host: string;
  port: number;
}

export const loadSettings = Effect.gen(function* () {
  const baseURL = yield* Config.string("AUTH_BASE_URL");
  const secret = Redacted.value(yield* Config.redacted("BETTER_AUTH_SECRET"));
  const database = yield* Config.string("AUTH_DATABASE").pipe(
    Config.withDefault("data/auth.sqlite"),
  );
  const host = yield* Config.string("HOST").pipe(Config.withDefault("127.0.0.1"));
  const port = yield* Config.number("PORT").pipe(Config.withDefault(3000));
  return yield* Effect.try(() => validateSettings({ baseURL, secret, database, host, port }));
});

export function validateSettings(settings: Settings): Settings {
  const url = new URL(settings.baseURL);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    url.origin !== settings.baseURL ||
    url.username ||
    url.password ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
  ) {
    throw new Error("AUTH_BASE_URL must be an HTTPS origin (HTTP allowed only on loopback)");
  }
  if (settings.secret.length < 32)
    throw new Error("BETTER_AUTH_SECRET must have at least 32 characters");
  if (!Number.isInteger(settings.port) || settings.port < 1 || settings.port > 65535)
    throw new Error("Invalid PORT");
  return settings;
}
