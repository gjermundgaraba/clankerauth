/**
 * A signing fake issuer for tests: the two endpoints a resource server actually calls,
 * and nothing else. Use it where a real issuer would make a test slow or awkward — a
 * token that must expire in two seconds, a key granted on someone else's resource, an
 * outage — and `@gjermundgaraba/clankerauth-dev` where the protocol itself is under test.
 *
 * It signs with a real EdDSA key and publishes it as JWKS, so every token and key list
 * still travels the resource server's own verifier: signature, issuer, audience, type,
 * claims, scopes, and each key's sealed entry. Node only.
 */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { Option, Schema } from "effect";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import * as KeyList from "./key-list.ts";

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
  /** The scopes a signed token, and a key minted without permissions, carry. */
  readonly scopes: readonly string[];
  /** Who every credential belongs to. Default `"owner"`. */
  readonly subject?: string;
}

/** Resource identifier to the scopes a key has there, as the real issuer takes them. */
export type Permissions = Readonly<Record<string, readonly string[]>>;

export interface FakeIssuer {
  /** What a resource server is configured with: `http://127.0.0.1:<port>/api/auth`. */
  readonly issuer: string;
  /** Sign an access token this issuer's JWKS verifies. */
  readonly sign: (claims?: TokenClaims, typ?: string) => Promise<string>;
  /**
   * Mint an API key, listed in each granted resource's key list from its next read.
   * Default permissions: every configured scope on the configured resource. `expiresAt`
   * is when the key stops verifying; default never. Key IDs are `key-1`, `key-2`, ….
   */
  readonly apiKey: (permissions?: Permissions, expiresAt?: Date) => string;
  /** Leave a minted key out of every key list from now on, as the real issuer does. */
  readonly revoke: (key: string) => void;
  /** Answer both endpoints with this status instead of serving them; omit to restore. */
  readonly fail: (status?: number) => void;
  /** Key lists served, so a test can see when a resource server reads its next one. */
  readonly keyLists: () => number;
  readonly close: () => Promise<void>;
}

const ListRequest = Schema.fromJsonString(Schema.Struct({ resource: Schema.String }));

export const startFakeIssuer = async (options: FakeIssuerOptions): Promise<FakeIssuer> => {
  const subject = options.subject ?? "owner";
  const pair = await generateKeyPair("EdDSA");
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: "fixture", alg: "EdDSA", use: "sig" };

  const keys = new Map<
    string,
    { keyId: string; permissions: Permissions; expiresAt: number | null }
  >();

  let minted = 0;
  let lists = 0;
  let failure: number | undefined;

  const server = createServer(async (request, response) => {
    const send = (status: number, body: string) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(body);
    };

    if (request.url === "/api/auth/jwks")
      return send(failure ?? 200, JSON.stringify({ keys: [jwk] }));

    if (request.url !== "/api/issuer/keyList" || request.method !== "POST") return send(404, "{}");
    lists++;

    if (failure !== undefined) return send(failure, "{}");
    let text = "";

    for await (const chunk of request) text += String(chunk);
    const asked = Schema.decodeUnknownOption(ListRequest)(text);

    if (Option.isNone(asked)) return send(400, '{"error":"Invalid request"}');
    const { resource } = asked.value;

    // Like the real issuer, a list holds only what is granted on the resource it names,
    // and only what has not expired.
    const now = Date.now();

    const entries = await Promise.all(
      [...keys].flatMap(([key, { keyId, permissions, expiresAt }]) => {
        const scopes = permissions[resource] ?? [];

        return scopes.length && (expiresAt === null || expiresAt > now)
          ? [
              KeyList.digest(key).then((digest) =>
                KeyList.seal(digest, resource, { keyId, ownerId: subject, scopes, expiresAt }),
              ),
            ]
          : [];
      }),
    );

    const iat = Math.floor(now / 1000);

    const list = await new SignJWT({ keys: entries })
      .setProtectedHeader({ alg: "EdDSA", kid: "fixture", typ: KeyList.type })
      .setIssuer(issuer)
      .setAudience(resource)
      .setIssuedAt(iat)
      .setExpirationTime(iat + KeyList.lifetime)
      .sign(pair.privateKey);

    return send(200, JSON.stringify({ list }));
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
    apiKey: (permissions = { [options.resource]: options.scopes }, expiresAt) => {
      const key = `clankerauth_${randomBytes(48).toString("base64url")}`;

      keys.set(key, {
        keyId: `key-${++minted}`,
        permissions,
        expiresAt: expiresAt?.getTime() ?? null,
      });

      return key;
    },
    revoke: (key) => {
      keys.delete(key);
    },
    fail: (status) => {
      failure = status;
    },
    keyLists: () => lists,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
};
