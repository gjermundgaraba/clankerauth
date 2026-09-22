import { isIP } from "node:net";
import { Config, Effect, Redacted, Schema } from "effect";

export interface Settings {
  baseURL: string;
  secret: Redacted.Redacted<string>;
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

/** `hostname` is `domain` or one of its subdomains. */
export const withinDomain = (hostname: string, domain: string) =>
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
export const allowedScheme = (url: URL, allowInsecureHttp: boolean) =>
  url.protocol === "https:" ||
  (url.protocol === "http:" &&
    (["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) || allowInsecureHttp));

const originHelp =
  "HTTPS origins (HTTP allowed on loopback, or anywhere with ALLOW_INSECURE_HTTP=true)";

/** A bare origin: any path, query, fragment or credentials would stop matching what clients send. */
const validOrigin = (value: string, allowInsecureHttp: boolean) =>
  URL.canParse(value) &&
  new URL(value).origin === value &&
  allowedScheme(new URL(value), allowInsecureHttp);

/** The rules between settings, for the environment and for embedders that build them directly. */
export const validateSettings = Effect.fnUntraced(function* (settings: Settings) {
  const { allowInsecureHttp, baseURL, cookieDomain } = settings;

  if (!validOrigin(baseURL, allowInsecureHttp))
    return yield* Effect.fail(new Error(`AUTH_BASE_URL must be one of: ${originHelp}`));

  // Signing keys and session cookies are only as strong as this value.
  if (Redacted.value(settings.secret).length < 32)
    return yield* Effect.fail(new Error("BETTER_AUTH_SECRET must have at least 32 characters"));

  if (!settings.mcpAllowedOrigins.every((origin) => validOrigin(origin, allowInsecureHttp)))
    return yield* Effect.fail(new Error(`MCP_ALLOWED_ORIGINS must contain exact ${originHelp}`));

  if (
    cookieDomain !== undefined &&
    (!cookieDomainValid(cookieDomain) || !withinDomain(new URL(baseURL).hostname, cookieDomain))
  )
    return yield* Effect.fail(
      new Error(
        "AUTH_COOKIE_DOMAIN must be a bare parent domain of the AUTH_BASE_URL host, such as home.example",
      ),
    );

  return settings;
});

export const loadSettings = Effect.gen(function* () {
  const settings: Settings = {
    baseURL: yield* Config.String("AUTH_BASE_URL"),
    secret: yield* Config.Redacted("BETTER_AUTH_SECRET"),
    database: yield* Config.String("AUTH_DATABASE").pipe(Config.withDefault("data/auth.sqlite")),
    host: yield* Config.String("HOST").pipe(Config.withDefault("127.0.0.1")),
    port: yield* Config.Port("PORT").pipe(Config.withDefault(3000)),
    mcpAllowedOrigins: yield* Config.Array(Schema.Trim, "MCP_ALLOWED_ORIGINS").pipe(
      Config.withDefault<readonly string[]>([]),
    ),
    trustProxy: yield* Config.Boolean("TRUST_PROXY").pipe(Config.withDefault(false)),
    allowInsecureHttp: yield* Config.Boolean("ALLOW_INSECURE_HTTP").pipe(Config.withDefault(false)),
    cookieDomain: yield* Config.String("AUTH_COOKIE_DOMAIN").pipe(Config.withDefault(undefined)),
  };

  return yield* validateSettings(settings);
});
