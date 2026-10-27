import { isIP } from "node:net";

import { Config, Context, Effect, Layer, Redacted, Schema } from "effect";

import { InvalidSettings } from "./errors.ts";

export interface IssuerSettings {
  baseURL: string;
  secret: Redacted.Redacted;
  database: string;
  host: string;
  port: number;
  /** Additional browser origins allowed to call MCP with OAuth bearer tokens. */
  mcpAllowedOrigins: readonly string[];
  /** Take the client address from the last X-Forwarded-For hop set by a trusted reverse proxy. */
  trustProxy: boolean;
  /** Permit a plain-HTTP issuer beyond loopback, for private networks without TLS. */
  allowInsecureHttp: boolean;
  /** Parent domain the forward cookie is scoped to, so forward auth covers sibling hosts. */
  cookieDomain: string | undefined;
}

export const withinDomain = (hostname: string, domain: string) =>
  hostname === domain || hostname.endsWith(`.${domain}`);

const cookieDomainValid = (domain: string) => {
  try {
    return (
      new URL(`https://${domain}`).hostname === domain &&
      domain.includes(".") &&
      !isIP(domain)
    );
  } catch {
    return false;
  }
};

export const allowedScheme = (url: URL, allowInsecureHttp: boolean) =>
  url.protocol === "https:" ||
  (url.protocol === "http:" &&
    (["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
      allowInsecureHttp));

const originHelp =
  "HTTPS origins (HTTP allowed on loopback, or anywhere with CLANKERAUTH_ALLOW_INSECURE_HTTP=true)";

const validOrigin = (value: string, allowInsecureHttp: boolean) =>
  URL.canParse(value) &&
  new URL(value).origin === value &&
  allowedScheme(new URL(value), allowInsecureHttp);

export const validateSettings = Effect.fnUntraced(function* (
  settings: IssuerSettings
) {
  const { allowInsecureHttp, baseURL, cookieDomain } = settings;

  if (!validOrigin(baseURL, allowInsecureHttp)) {
    return yield* new InvalidSettings({
      message: `CLANKERAUTH_BASE_URL must be one of: ${originHelp}`,
    });
  }

  if (Redacted.value(settings.secret).length < 32) {
    return yield* new InvalidSettings({
      message:
        "CLANKERAUTH_BETTER_AUTH_SECRET must have at least 32 characters",
    });
  }

  if (
    !settings.mcpAllowedOrigins.every((origin) =>
      validOrigin(origin, allowInsecureHttp)
    )
  ) {
    return yield* new InvalidSettings({
      message: `CLANKERAUTH_MCP_ALLOWED_ORIGINS must contain exact ${originHelp}`,
    });
  }

  if (
    cookieDomain !== undefined &&
    (!cookieDomainValid(cookieDomain) ||
      !withinDomain(new URL(baseURL).hostname, cookieDomain))
  ) {
    return yield* new InvalidSettings({
      message:
        "CLANKERAUTH_COOKIE_DOMAIN must be a bare parent domain of the CLANKERAUTH_BASE_URL host, such as home.example",
    });
  }

  return settings;
});

export const loadSettings = Effect.gen(function* () {
  const settings: IssuerSettings = {
    baseURL: yield* Config.String("CLANKERAUTH_BASE_URL"),
    secret: yield* Config.Redacted("CLANKERAUTH_BETTER_AUTH_SECRET"),
    database: yield* Config.String("CLANKERAUTH_DATABASE").pipe(
      Config.withDefault("data/clankerauth.sqlite")
    ),
    host: yield* Config.String("CLANKERAUTH_HOST").pipe(
      Config.withDefault("127.0.0.1")
    ),
    port: yield* Config.Port("CLANKERAUTH_PORT").pipe(Config.withDefault(3000)),
    mcpAllowedOrigins: yield* Config.Array(
      Schema.Trim,
      "CLANKERAUTH_MCP_ALLOWED_ORIGINS"
    ).pipe(Config.withDefault<readonly string[]>([])),
    trustProxy: yield* Config.Boolean("CLANKERAUTH_TRUST_PROXY").pipe(
      Config.withDefault(false)
    ),
    allowInsecureHttp: yield* Config.Boolean(
      "CLANKERAUTH_ALLOW_INSECURE_HTTP"
    ).pipe(Config.withDefault(false)),
    cookieDomain: yield* Config.String("CLANKERAUTH_COOKIE_DOMAIN").pipe(
      Config.withDefault(undefined)
    ),
  };

  return yield* validateSettings(settings);
});

export class Settings extends Context.Service<Settings, IssuerSettings>()(
  "clankerauth/Settings"
) {
  static readonly layer = Layer.effect(Settings, loadSettings);
}
