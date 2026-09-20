/** A protocol fixture standing in for an issuer: JWKS and API-key verification only. */
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { Result, Schema } from "effect";
import type { JWTPayload } from "jose";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

export const publicUrl = "http://127.0.0.1:7337";

const VerifyRequest = Schema.fromJsonString(Schema.Struct({ resource: Schema.String }));

export const startIssuer = async () => {
  const pair = await generateKeyPair("EdDSA");
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: "fixture", alg: "EdDSA" };
  const key = `ca_${randomBytes(32).toString("base64url")}`;
  const readOnlyKey = `ca_${randomBytes(32).toString("base64url")}`;

  const keys = new Map([
    [key, ["notes:read", "notes:write"]],
    [readOnlyKey, ["notes:read"]],
  ]);

  let verificationCount = 0;
  let failure: number | undefined;
  let malformed = false;

  const server = createServer(async (request, response) => {
    const send = (status: number, body: string) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(body);
    };

    if (request.url === "/api/auth/jwks")
      return send(failure ?? 200, JSON.stringify({ keys: [jwk] }));

    if (request.url !== "/api/issuer/verifyApiKey") return send(404, "{}");
    verificationCount++;

    if (failure) return send(failure, "{}");
    const value = request.headers.authorization?.slice(7);
    const scopes = value && keys.get(value);

    if (!scopes) return send(401, "{}");
    let text = "";

    for await (const chunk of request) text += String(chunk);
    const parsed = Schema.decodeUnknownResult(VerifyRequest)(text);

    if (Result.isFailure(parsed)) return send(400, "{}");
    const { resource } = parsed.success;

    if (![`${publicUrl}/api`, `${publicUrl}/mcp`].includes(resource)) return send(403, "{}");

    if (malformed) return send(200, JSON.stringify({ keyId: "writer" }));

    return send(
      200,
      JSON.stringify({
        keyId: value === key ? "writer" : "reader",
        ownerId: "owner",
        resource,
        scopes,
        expiresAt: null,
      }),
    );
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();

  if (address === null || !(address instanceof Object) || !("port" in address))
    throw new Error("No address");
  const issuer = `http://127.0.0.1:${address.port}/api/auth`;

  return {
    issuer,
    key,
    readOnlyKey,
    keys,
    count: () => verificationCount,
    fail: (status?: number) => {
      failure = status;
    },
    malform: (value: boolean) => {
      malformed = value;
    },
    sign: (claims: JWTPayload = {}, surface = "api", typ = "at+jwt") =>
      new SignJWT({
        sub: "owner",
        iss: issuer,
        aud: `${publicUrl}/${surface}`,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        client_id: "fixture",
        grant_generation: "fixture-generation",
        scope: "notes:read notes:write",
        ...claims,
      })
        .setProtectedHeader({ alg: "EdDSA", kid: "fixture", typ })
        .sign(pair.privateKey),
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
};
