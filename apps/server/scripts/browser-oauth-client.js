import { auth, Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

// A browser-owned OAuth client. Persist the flow across real issuer navigation.
const read = (key) => JSON.parse(sessionStorage.getItem(key) ?? "null") ?? undefined;
const write = (key, value) => sessionStorage.setItem(key, JSON.stringify(value));
const issuer = new URLSearchParams(location.search).get("issuer") ?? read("issuer");
write("issuer", issuer);
const serverUrl = new URL("/mcp", issuer);
const provider = {
  redirectUrl: `${location.origin}/callback`,
  clientMetadata: {
    client_name: "Cross-origin browser MCP test",
    redirect_uris: [`${location.origin}/callback`],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  },
  state: () => {
    const state = crypto.randomUUID();
    write("state", state);
    return state;
  },
  clientInformation: () => read("client"),
  saveClientInformation: (value) => write("client", value),
  tokens: () => read("tokens"),
  saveTokens: (value) => write("tokens", value),
  saveCodeVerifier: (value) => write("verifier", value),
  codeVerifier: () => read("verifier"),
  saveAuthorizationServerUrl: (value) => write("authorizationServer", value),
  authorizationServerUrl: () => read("authorizationServer"),
  redirectToAuthorization: (url) => write("authorizationUrl", url.href),
};
let client;
let transport;

window.mcpTest = {
  async inspectDiscovery() {
    const response = await fetch(serverUrl, { method: "POST" });
    const resource = await fetch(new URL("/.well-known/oauth-protected-resource/mcp", issuer));
    return {
      status: response.status,
      challenge: response.headers.get("www-authenticate"),
      resource: await resource.json(),
    };
  },
  async connect(mode = "modern") {
    client = new Client({ name: "browser-oauth-test", version: "1" });
    transport = new StreamableHTTPClientTransport(serverUrl, { authProvider: provider });
    try {
      await client.connect(transport, { mode });
      return { connected: true, sessionId: transport.sessionId };
    } catch (error) {
      if (!read("authorizationUrl")) throw error;
      return { authorizationUrl: read("authorizationUrl") };
    }
  },
  async finishAuth() {
    const callback = new URLSearchParams(location.search);
    if (!callback.get("state") || callback.get("state") !== read("state")) {
      throw new Error("OAuth callback state mismatch");
    }
    const exchange = new StreamableHTTPClientTransport(serverUrl, { authProvider: provider });
    await exchange.finishAuth(callback);
    sessionStorage.removeItem("authorizationUrl");
    return { hasRefreshToken: typeof read("tokens").refresh_token === "string" };
  },
  async tools() {
    return (await client.listTools()).tools.map((tool) => tool.name);
  },
  async createClient() {
    return client.callTool({
      name: "createClient",
      arguments: {
        name: "Created by browser MCP",
        redirect: "https://managed.example.internal/callback",
        resources: [serverUrl.href],
        confidential: false,
        native: false,
      },
    });
  },
  async refresh() {
    const previous = read("tokens");
    const result = await auth(provider, { serverUrl });
    return {
      result,
      rotated: previous.refresh_token !== read("tokens").refresh_token,
      hasAccessToken: typeof read("tokens").access_token === "string",
    };
  },
  close: () => client.close(),
};
