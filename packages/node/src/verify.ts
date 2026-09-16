import { createRemoteJWKSet, errors, jwtVerify } from "jose";
import { AuthError, IssuerResponseError, type AuthErrorCode } from "./errors.ts";

/** Who a request acts as. The subject is always the issuer's owner; the actor is the credential that acted. */
export interface Principal {
  readonly subject: string;
  readonly scopes: readonly string[];
  readonly actor:
    | { readonly kind: "client"; readonly clientId: string }
    | { readonly kind: "key"; readonly keyId: string };
}

export interface VerifierOptions {
  /** Issuer identifier, for example `https://auth.internal/api/auth`. */
  readonly issuer: string;
  /** Exact audience URL of this resource, for example `https://notes.internal/api`. */
  readonly resource: string;
  /** Scopes every credential needs before a request is authenticated at all. */
  readonly requiredScopes?: readonly string[];
  /** Observes failures that are not credential outcomes: outages, malformed issuer responses. */
  readonly onFailure?: (operation: string, error: unknown) => void | Promise<void>;
}

export interface Verifier {
  /** Verify an `Authorization` header value: a JWT access token or a `ca_` API key. */
  readonly verify: (authorization: string | null | undefined) => Promise<Principal>;
  /** Verify a bare access token or API key. */
  readonly verifyToken: (token: string) => Promise<Principal>;
}

const timeout = 5000;
const credentialErrors = [
  errors.JWTExpired,
  errors.JWTClaimValidationFailed,
  errors.JWSSignatureVerificationFailed,
  errors.JWSInvalid,
  errors.JWTInvalid,
  errors.JOSENotSupported,
  errors.JOSEAlgNotAllowed,
  errors.JWKSNoMatchingKey,
];
/** Verification statuses that are credential outcomes rather than outages. */
const outcomes: Record<number, AuthErrorCode | undefined> = {
  401: "unauthorized",
  403: "forbidden",
  429: "rate_limited",
};
const nonEmpty = (value: unknown): value is string => typeof value === "string" && value.length > 0;
const scopeList = (value: unknown): readonly string[] | undefined =>
  Array.isArray(value) && value.every(nonEmpty) ? value : undefined;

export function createVerifier(options: VerifierOptions): Verifier {
  const { issuer, resource, requiredScopes = [] } = options;
  const report = async (operation: string, error: unknown) => {
    await options.onFailure?.(operation, error);
  };
  const jwks = createRemoteJWKSet(new URL(`${issuer}/jwks`), { timeoutDuration: timeout });
  const verifyJwt = async (token: string): Promise<Principal> => {
    let payload;
    try {
      ({ payload } = await jwtVerify(token, jwks, {
        issuer,
        audience: resource,
        algorithms: ["EdDSA"],
        typ: "at+jwt",
        requiredClaims: ["sub", "client_id", "scope", "iat", "exp"],
      }));
    } catch (error) {
      if (credentialErrors.some((kind) => error instanceof kind))
        throw new AuthError("unauthorized");
      await report("jwt.verify", error);
      throw new AuthError("unavailable");
    }
    // Sender-constrained tokens need proof this verifier does not check.
    if (payload.cnf !== undefined) throw new AuthError("unauthorized");
    if (!nonEmpty(payload.sub) || !nonEmpty(payload.client_id) || typeof payload.scope !== "string")
      throw new AuthError("unauthorized");
    return {
      subject: payload.sub,
      scopes: payload.scope.split(" ").filter(Boolean),
      actor: { kind: "client", clientId: payload.client_id },
    };
  };
  const verifyKey = async (key: string): Promise<Principal> => {
    let response: Response;
    try {
      response = await fetch(new URL("/api/verifyApiKey", issuer), {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(timeout),
        headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
        body: JSON.stringify({ resource }),
      });
    } catch (error) {
      await report("api-key.verify", error);
      throw new AuthError("unavailable");
    }
    if (!response.ok) {
      await response.body?.cancel();
      const code = outcomes[response.status];
      if (code) throw new AuthError(code);
      await report("api-key.verify", new IssuerResponseError(response.status));
      throw new AuthError("unavailable");
    }
    let verified: unknown;
    try {
      verified = await response.json();
    } catch (error) {
      await report("api-key.response", error);
      throw new AuthError("unavailable");
    }
    const record = typeof verified === "object" && verified !== null ? verified : {};
    const {
      keyId,
      ownerId,
      resource: echoed,
      scopes,
      expiresAt,
    } = record as Record<string, unknown>;
    const expiry =
      expiresAt === null ? null : typeof expiresAt === "string" ? Date.parse(expiresAt) : NaN;
    const verifiedScopes = scopeList(scopes);
    if (
      !nonEmpty(keyId) ||
      !nonEmpty(ownerId) ||
      echoed !== resource ||
      !verifiedScopes ||
      (expiry !== null && !Number.isFinite(expiry))
    ) {
      await report("api-key.response", new Error("Verification response is malformed"));
      throw new AuthError("unavailable");
    }
    if (expiry !== null && expiry <= Date.now()) throw new AuthError("unauthorized");
    return { subject: ownerId, scopes: verifiedScopes, actor: { kind: "key", keyId } };
  };
  const verifyToken = async (token: string): Promise<Principal> => {
    const principal = await (token.startsWith("ca_") ? verifyKey(token) : verifyJwt(token));
    if (requiredScopes.some((scope) => !principal.scopes.includes(scope)))
      throw new AuthError("forbidden");
    return principal;
  };
  return {
    verifyToken,
    verify: async (authorization) => {
      const token = /^Bearer ([^\s,]+)$/iu.exec(authorization ?? "")?.[1];
      if (!token) throw new AuthError("unauthorized");
      return verifyToken(token);
    },
  };
}
