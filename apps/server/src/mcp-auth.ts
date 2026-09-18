import { Effect, Schema } from "effect";
import { HttpServerRequest } from "effect/unstable/http";
import { createLocalJWKSet, jwtVerify } from "jose";
import { Forbidden, Unauthorized } from "@clankerauth/api";
import { apiError } from "./api-errors.ts";
import type { Service } from "./auth.ts";
import { providerSession } from "./provider-session.ts";
import { mcpResource, mcpScope } from "./resources.ts";

const claims = Schema.Struct({
  sub: Schema.String,
  client_id: Schema.String,
  azp: Schema.String,
  scope: Schema.String,
  grant_generation: Schema.String,
  exp: Schema.Number,
});

const invalidToken = () => new Unauthorized({ error: "Valid MCP bearer token required" });

/** OAuth authority is checked before acquiring an internal provider session. */
export const mcpAuthentication = (service: Service) =>
  Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const authorization = request.headers.authorization;

    if (!authorization)
      return yield* Effect.fail(new Unauthorized({ error: "OAuth access token required" }));
    const match = authorization.match(/^Bearer ([^\s]+)$/i);

    if (!match) return yield* Effect.fail(invalidToken());

    const jwks = yield* Effect.tryPromise({
      try: () => service.auth.api.getJwks(),
      catch: apiError,
    });

    const verified = yield* Effect.tryPromise({
      try: () =>
        jwtVerify(match[1], createLocalJWKSet(jwks), {
          issuer: `${service.settings.baseURL}/api/auth`,
          audience: mcpResource(service.settings.baseURL),
          algorithms: ["EdDSA"],
          typ: "at+jwt",
          requiredClaims: [
            "sub",
            "client_id",
            "azp",
            "scope",
            "exp",
            "iat",
            "jti",
            "grant_generation",
          ],
        }),
      catch: invalidToken,
    });

    const token = yield* Schema.decodeUnknownEffect(claims)(verified.payload).pipe(
      Effect.mapError(invalidToken),
    );

    // Sender-constrained tokens cannot be used as ordinary bearer credentials.
    if (verified.payload.cnf !== undefined || token.client_id !== token.azp)
      return yield* Effect.fail(invalidToken());

    const ownerRows = yield* service.sql`SELECT u.id, u.email FROM user u
    JOIN serviceOwner o ON o.userId = u.id WHERE o.id = 1 AND u.id = ${token.sub}`.pipe(
      Effect.mapError(apiError),
    );

    if (!ownerRows[0]) return yield* Effect.fail(invalidToken());

    const owner = yield* Schema.decodeUnknownEffect(
      Schema.Struct({ id: Schema.String, email: Schema.String }),
    )(ownerRows[0]).pipe(Effect.mapError(apiError));

    const authorized = yield* service.sql`SELECT 1 FROM oauthClient c
    JOIN oauthClientResource r ON r.clientId = c.clientId AND r.resourceId = ${mcpResource(service.settings.baseURL)}
    WHERE c.clientId = ${token.client_id} AND c.disabled IS NOT 1
      AND c.grantGeneration = ${token.grant_generation}
      AND NOT EXISTS (SELECT 1 FROM clientOnboarding p WHERE p.clientId = c.clientId AND p.blocked = 1)`.pipe(
      Effect.mapError(apiError),
    );

    if (!authorized.length) return yield* Effect.fail(invalidToken());

    if (!token.scope.split(" ").includes(mcpScope))
      return yield* Effect.fail(new Forbidden({ error: "The admin scope is required" }));

    return {
      userId: owner.id,
      email: owner.email,
      providerHeaders: providerSession(service, owner.id, token.exp),
    };
  });
