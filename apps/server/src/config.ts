import { isIP } from "node:net";
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
  /** Parent domain the forward cookie is scoped to, so forward auth covers sibling hosts. */
  cookieDomain: string | undefined;
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

  const cookieDomain = yield* Config.String("AUTH_COOKIE_DOMAIN").pipe(
    Config.withDefault(undefined),
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
      cookieDomain,
    }),
  );
});

/** `hostname` is `domain` or one of its subdomains. */
const withinDomain = (hostname: string, domain: string) =>
  hostname === domain || hostname.endsWith(`.${domain}`);

/** Browsers silently drop cookies scoped to a bare TLD or an IP address. */
const cookieDomainValid = (domain: string) => {
  try {
    return (
      new URL(`https://${domain}`).hostname === domain && domain.includes(".") && !isIP(domain)
    );
  } catch {
    return false;
  }
};

/** HTTPS, or HTTP on loopback or anywhere with ALLOW_INSECURE_HTTP. */
const allowedScheme = (url: URL, allowInsecureHttp: boolean) =>
  url.protocol === "https:" ||
  (url.protocol === "http:" &&
    (["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) || allowInsecureHttp));

const validOrigin = (value: string, allowInsecureHttp: boolean) => {
  try {
    const url = new URL(value);

    return url.origin === value && allowedScheme(url, allowInsecureHttp);
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

  if (
    settings.cookieDomain !== undefined &&
    (!cookieDomainValid(settings.cookieDomain) ||
      !withinDomain(new URL(settings.baseURL).hostname, settings.cookieDomain))
  )
    throw new Error(
      "AUTH_COOKIE_DOMAIN must be a bare parent domain of the AUTH_BASE_URL host, such as home.example",
    );

  return { ...settings, mcpAllowedOrigins };
}

/** The forwarded request's URL may be returned to after login: same scheme policy as the issuer,
 * and a host the owner session cookie reaches (the issuer host, or the shared cookie domain). */
export const allowedReturnURL = (settings: Settings, value: string) => {
  let url: URL;

  try {
    url = new URL(value);
  } catch {
    return undefined;
  }

  if (url.username || url.password || !allowedScheme(url, settings.allowInsecureHttp))
    return undefined;
  const issuerHost = new URL(settings.baseURL).hostname;

  return url.hostname === issuerHost ||
    (settings.cookieDomain !== undefined && withinDomain(url.hostname, settings.cookieDomain))
    ? url
    : undefined;
};
