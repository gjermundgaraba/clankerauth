import { createHash, randomBytes } from "node:crypto";

import { Effect, Schema } from "effect";
import { expect } from "vite-plus/test";

import { peerHeader } from "../src/platform/node-http.ts";

export const administrationResource = (baseURL: string) => ({
  identifier: `${baseURL}/`,
  name: "clankerauth administration",
  scopes: ["clankerauth:read", "clankerauth:write"],
  builtIn: true,
});

export type TestHandler = (request: Request) => Promise<Response>;

export const decodeJson =
  <S extends Schema.Decoder<unknown>>(schema: S) =>
  (response: Response) =>
    Effect.flatMap(
      Effect.promise(async () => await response.clone().text()),
      Schema.decodeUnknownEffect(Schema.fromJsonString(schema))
    );

export const Tokens = Schema.Struct({
  access_token: Schema.String,
  expires_in: Schema.Finite,
  refresh_token: Schema.String,
  scope: Schema.String,
});

export const Jwks = Schema.Struct({
  keys: Schema.mutable(
    Schema.Array(Schema.Record(Schema.String, Schema.Unknown))
  ),
});

interface GrantOptions {
  resource?: string;
  scope?: string;
  granted?: string;
  clientId?: string;
}

interface ConsentDecision {
  accept: boolean;
  oauth_query: string;
  scope?: string;
}

export const oauthToken = async (
  handle: TestHandler,
  baseURL: string,
  form: Record<string, string>
) =>
  await handle(
    new Request(`${baseURL}/api/auth/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form),
    })
  );

export const mcpOAuthCode = async (
  handle: TestHandler,
  baseURL: string,
  cookie: string,
  options: GrantOptions = {}
) => {
  const resource = options.resource ?? `${baseURL}/`;
  const callback = "http://127.0.0.1:9876/callback";
  let client_id = options.clientId;

  if (client_id === undefined) {
    const registration = await handle(
      new Request(`${baseURL}/api/auth/oauth2/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          [peerHeader]: "127.0.0.1",
        },
        body: JSON.stringify({
          client_name: "MCP OAuth integration test",
          redirect_uris: [callback],
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
        }),
      })
    );

    expect(registration.status, await registration.clone().text()).toBe(201);
    const registered: unknown = await registration.json();

    ({ client_id } = Schema.decodeUnknownSync(
      Schema.Struct({ client_id: Schema.String })
    )(registered));
  }

  const verifier = randomBytes(32).toString("base64url");

  const authorization = await handle(
    new Request(
      `${baseURL}/api/auth/oauth2/authorize?${new URLSearchParams({
        client_id,
        redirect_uri: callback,
        response_type: "code",
        resource,
        scope:
          options.scope ?? "offline_access clankerauth:read clankerauth:write",
        code_challenge: createHash("sha256")
          .update(verifier)
          .digest("base64url"),
        code_challenge_method: "S256",
        state: "mcp-oauth-test",
      })}`,
      { headers: { cookie } }
    )
  );

  expect(authorization.status, await authorization.clone().text()).toBe(302);

  const location = new URL(
    authorization.headers.get("location") ?? "",
    baseURL
  );

  expect(location.pathname).toBe("/consent");

  const decision: ConsentDecision = {
    accept: true,
    oauth_query: location.search.slice(1),
  };

  if (options.granted !== undefined) {
    decision.scope = options.granted;
  }

  const consent = await handle(
    new Request(`${baseURL}/api/auth/oauth2/consent`, {
      method: "POST",
      headers: { cookie, origin: baseURL, "content-type": "application/json" },
      body: JSON.stringify(decision),
    })
  );

  expect(consent.status, await consent.clone().text()).toBe(200);
  const consented: unknown = await consent.json();

  const redirect = new URL(
    Schema.decodeUnknownSync(Schema.Struct({ url: Schema.String }))(consented)
      .url
  );

  expect(redirect.searchParams.get("state")).toBe("mcp-oauth-test");
  expect(redirect.searchParams.get("iss")).toBe(`${baseURL}/api/auth`);

  return {
    grant_type: "authorization_code",
    client_id,
    redirect_uri: callback,
    code: redirect.searchParams.get("code") ?? "",
    code_verifier: verifier,
    resource,
  };
};

export const mcpOAuthGrant = async (
  handle: TestHandler,
  baseURL: string,
  cookie: string,
  options: GrantOptions & {
    exchange?: (form: Record<string, string>) => Promise<Response>;
  } = {}
) => {
  const form = await mcpOAuthCode(handle, baseURL, cookie, options);

  const token = await (
    options.exchange ??
    (async (code) => await oauthToken(handle, baseURL, code))
  )(form);

  expect(token.status, await token.clone().text()).toBe(200);
  const granted: unknown = await token.json();
  const tokens = Schema.decodeUnknownSync(Tokens)(granted);

  return { client_id: form.client_id, tokens };
};
