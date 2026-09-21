/**
 * A signing fake issuer for tests: the two endpoints a resource server actually calls,
 * and nothing else. Use it where a real issuer would make a test slow or awkward — a
 * token that must expire in two seconds, a key granted on someone else's resource, an
 * outage — and `startDisposableIssuer` where the protocol itself is under test.
 *
 * It signs with a real EdDSA key and publishes it as JWKS, so every token still travels
 * the resource server's own verifier: signature, issuer, audience, type, claims, scopes.
 */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

/** Claims set on a signed token. Each one overrides this issuer's default. */
export interface TokenClaims {
  readonly iss?: string;
  readonly sub?: string;
  readonly aud?: string | Array<string>;
  readonly iat?: number;
  /** Epoch seconds. Default: five minutes from now. */
  readonly exp?: number;
  /** Space-separated, as the wire carries it. */
  readonly scope?: string;
  readonly client_id?: string;
  /** Proof of possession, for checking that a sender-constrained token is refused. */
  readonly cnf?: { readonly jkt: string };
}

export interface FakeIssuerOptions {
  /** The resource identifier tokens are minted for: an application's public origin root. */
  readonly resource: string;
  /** The scopes a signed token carries unless the caller names its own. */
  readonly scopes: readonly string[];
  /** Who every credential belongs to. Default `"owner"`. */
  readonly subject?: string;
}

export interface FakeIssuer {
  /** What a resource server is configured with: `http://127.0.0.1:<port>/api/auth`. */
  readonly issuer: string;
  /** Sign an access token this issuer's JWKS verifies. */
  readonly sign: (claims?: TokenClaims, typ?: string) => Promise<string>;
  /** Mint an API key the verification endpoint accepts, granted on one resource. */
  readonly apiKey: (scopes: readonly string[], resource?: string) => string;
  /** Stop accepting a minted key, so the next verification answers `401`. */
  readonly revoke: (key: string) => void;
  /** Answer both endpoints with this status instead of serving them; omit to restore. */
  readonly fail: (status?: number) => void;
  /** API-key verifications served, so a test can see that revocation is checked online. */
  readonly verifications: () => number;
  readonly close: () => Promise<void>;
}

const isString = (value: unknown): value is string => typeof value === "string";

/** The resource a verification request asks about, or `undefined` for a malformed body. */
const askedResource = (text: string): string | undefined => {
  try {
    const parsed: unknown = JSON.parse(text);

    if (!(parsed instanceof Object) || !("resource" in parsed)) return undefined;
    const asked: unknown = parsed.resource;

    return isString(asked) ? asked : undefined;
  } catch {
    return undefined;
  }
};

export const startFakeIssuer = async (options: FakeIssuerOptions): Promise<FakeIssuer> => {
  const subject = options.subject ?? "owner";
  const pair = await generateKeyPair("EdDSA");
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: "fixture", alg: "EdDSA", use: "sig" };
  const grants = new Map<string, { keyId: string; resource: string; scopes: readonly string[] }>();
  let verifications = 0;
  let failure: number | undefined;

  const server = createServer(async (request, response) => {
    const send = (status: number, body: string) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(body);
    };

    if (request.url === "/api/auth/jwks")
      return send(failure ?? 200, JSON.stringify({ keys: [jwk] }));

    if (request.url !== "/api/issuer/verifyApiKey" || request.method !== "POST")
      return send(404, "{}");
    verifications++;

    if (failure !== undefined) return send(failure, "{}");
    const grant = grants.get(request.headers.authorization?.replace(/^Bearer /iu, "") ?? "");

    if (grant === undefined) return send(401, '{"error":"Invalid API key"}');
    let text = "";

    for await (const chunk of request) text += String(chunk);
    const asked = askedResource(text);

    if (asked === undefined) return send(400, '{"error":"Invalid request"}');

    // The real issuer answers exactly this for a key with no grant on the resource.
    if (asked !== grant.resource) return send(403, '{"error":"No access to this Resource"}');

    return send(
      200,
      JSON.stringify({
        keyId: grant.keyId,
        ownerId: subject,
        resource: grant.resource,
        scopes: grant.scopes,
        expiresAt: null,
      }),
    );
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();

  if (!(address instanceof Object)) throw new Error("The fake issuer failed to bind a TCP port");
  const issuer = `http://127.0.0.1:${address.port}/api/auth`;

  return {
    issuer,
    sign: (claims = {}, typ = "at+jwt") => {
      const now = Math.floor(Date.now() / 1000);

      return new SignJWT({
        iss: issuer,
        sub: subject,
        aud: options.resource,
        iat: now,
        exp: now + 300,
        client_id: "fixture",
        scope: options.scopes.join(" "),
        ...claims,
      })
        .setProtectedHeader({ alg: "EdDSA", kid: "fixture", typ })
        .sign(pair.privateKey);
    },
    apiKey: (scopes, resource = options.resource) => {
      const key = `ca_${randomBytes(24).toString("base64url")}`;
      grants.set(key, { keyId: `key-${grants.size + 1}`, resource, scopes });

      return key;
    },
    revoke: (key) => {
      grants.delete(key);
    },
    fail: (status) => {
      failure = status;
    },
    verifications: () => verifications,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
};
