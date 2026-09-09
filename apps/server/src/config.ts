import { Config, Effect, Redacted, Schema } from "effect";

export const Resource = Schema.Struct({
  identifier: Schema.String,
  name: Schema.String,
  scopes: Schema.Array(Schema.String),
});
export type Resource = typeof Resource.Type;
export interface Settings {
  baseURL: string;
  secret: string;
  database: string;
  host: string;
  port: number;
  resources: readonly Resource[];
}

export const loadSettings = Effect.gen(function* () {
  const baseURL = yield* Config.string("AUTH_BASE_URL");
  const secret = Redacted.value(yield* Config.redacted("BETTER_AUTH_SECRET"));
  const database = yield* Config.string("AUTH_DATABASE").pipe(
    Config.withDefault("data/auth.sqlite"),
  );
  const host = yield* Config.string("HOST").pipe(Config.withDefault("127.0.0.1"));
  const port = yield* Config.number("PORT").pipe(Config.withDefault(3000));
  const raw = yield* Config.string("AUTH_RESOURCES");
  const resources = yield* Effect.try({
    try: () => Schema.decodeUnknownSync(Schema.Array(Resource))(JSON.parse(raw)),
    catch: () => new Error("AUTH_RESOURCES must be a JSON array of identifier, name and scopes"),
  });
  return yield* Effect.try(() =>
    validateSettings({ baseURL, secret, database, host, port, resources }),
  );
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
  if (!settings.resources.length) throw new Error("Configure at least one resource");
  const identifiers = new Set<string>();
  for (const resource of settings.resources) {
    const uri = new URL(resource.identifier);
    if (
      uri.protocol !== "https:" ||
      uri.hash ||
      uri.search ||
      uri.username ||
      uri.password ||
      identifiers.has(resource.identifier)
    ) {
      throw new Error(
        "Resource identifiers must be unique HTTPS URLs without credentials, query or fragment",
      );
    }
    if (
      !resource.name ||
      !resource.scopes.length ||
      resource.scopes.some((scope) => !/^[a-z][a-z0-9:-]+$/.test(scope))
    ) {
      throw new Error("Resources require a name and nonempty scope list");
    }
    identifiers.add(resource.identifier);
  }
  return settings;
}
