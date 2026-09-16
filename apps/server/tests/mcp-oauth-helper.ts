import { createHash, randomBytes } from "node:crypto";
import { expect } from "vite-plus/test";

export const administrationResource = (baseURL: string) => ({
  identifier: `${baseURL}/mcp`,
  name: "Clanker Auth administration",
  scopes: ["admin"],
  builtIn: true,
});

export type TestHandler = (request: Request) => Promise<Response>;

type GrantOptions = { resource?: string; scope?: string; clientId?: string };

/** A native MCP client registers anonymously; the owner grants access through consent. */
export async function mcpOAuthCode(
  handle: TestHandler,
  baseURL: string,
  cookie: string,
  options: GrantOptions = {},
) {
  const resource = options.resource ?? `${baseURL}/mcp`;
  const callback = "http://127.0.0.1:9876/callback";
  let client_id = options.clientId;
  if (!client_id) {
    const registration = await handle(
      new Request(`${baseURL}/api/auth/oauth2/register`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-clankerauth-peer": "127.0.0.1" },
        body: JSON.stringify({
          client_name: "MCP OAuth integration test",
          redirect_uris: [callback],
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
        }),
      }),
    );
    expect(registration.status, await registration.clone().text()).toBe(201);
    client_id = String((await registration.json()).client_id);
  }
  const verifier = randomBytes(32).toString("base64url");
  const authorization = await handle(
    new Request(
      `${baseURL}/api/auth/oauth2/authorize?${new URLSearchParams({
        client_id,
        redirect_uri: callback,
        response_type: "code",
        resource,
        scope: options.scope ?? "openid offline_access admin",
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256",
        state: "mcp-oauth-test",
      })}`,
      { headers: { cookie } },
    ),
  );
  expect(authorization.status, await authorization.clone().text()).toBe(302);
  const location = new URL(authorization.headers.get("location") ?? "", baseURL);
  expect(location.pathname).toBe("/consent");
  const consent = await handle(
    new Request(`${baseURL}/api/auth/oauth2/consent`, {
      method: "POST",
      headers: { cookie, origin: baseURL, "content-type": "application/json" },
      body: JSON.stringify({ accept: true, oauth_query: location.search.slice(1) }),
    }),
  );
  expect(consent.status, await consent.clone().text()).toBe(200);
  const redirect = new URL((await consent.json()).url);
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
}

export async function mcpOAuthGrant(
  handle: TestHandler,
  baseURL: string,
  cookie: string,
  options: GrantOptions & { exchange?: (form: Record<string, string>) => Promise<Response> } = {},
) {
  const form = await mcpOAuthCode(handle, baseURL, cookie, options);
  const token = await (options.exchange ?? ((form) => oauthToken(handle, baseURL, form)))(form);
  expect(token.status, await token.clone().text()).toBe(200);
  const tokens = await token.json();
  expect(tokens.access_token).toBeTypeOf("string");
  return { client_id: form.client_id, tokens };
}

export function oauthToken(handle: TestHandler, baseURL: string, form: Record<string, string>) {
  return handle(
    new Request(`${baseURL}/api/auth/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form),
    }),
  );
}
