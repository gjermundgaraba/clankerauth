import {
  auth,
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import type {
  OAuthClientProvider,
  StoredOAuthClientInformation,
  StoredOAuthTokens,
} from "@modelcontextprotocol/client";
import { Schema } from "effect";

// why: the SDK reads back what it saved: the fields it checks are typed, the rest kept as saved
const persisted = <const Fields extends Schema.Struct.Fields>(fields: Fields) =>
  Schema.fromJsonString(
    Schema.StructWithRest(Schema.Struct(fields), [
      Schema.Record(Schema.String, Schema.Json),
    ])
  );

const ClientInformation = persisted({
  client_id: Schema.String,
  client_secret: Schema.optional(Schema.String),
  client_id_issued_at: Schema.optional(Schema.Finite),
  client_secret_expires_at: Schema.optional(Schema.Finite),
  issuer: Schema.optional(Schema.String),
});

const Tokens = persisted({
  access_token: Schema.String,
  token_type: Schema.String,
  id_token: Schema.optional(Schema.String),
  expires_in: Schema.optional(Schema.Finite),
  scope: Schema.optional(Schema.String),
  refresh_token: Schema.optional(Schema.String),
  issuer: Schema.optional(Schema.String),
});

// why: sessionStorage carries the flow across real issuer navigations
const stored = (key: string) => sessionStorage.getItem(key) ?? undefined;

const store = (key: string, value: string) => {
  sessionStorage.setItem(key, value);
};

const decodeClientInformation = Schema.decodeSync(ClientInformation);

const decodeTokens = Schema.decodeSync(Tokens);

// why: nothing saved yet reads as undefined; anything saved that fails to decode throws
const clientInformation = (): StoredOAuthClientInformation | undefined => {
  const saved = stored("client");

  return saved === undefined ? undefined : decodeClientInformation(saved);
};

const tokens = (): StoredOAuthTokens | undefined => {
  const saved = stored("tokens");

  return saved === undefined ? undefined : decodeTokens(saved);
};

const issuer =
  new URLSearchParams(location.search).get("issuer") ?? stored("issuer");

if (issuer === undefined) {
  throw new Error("The page needs an issuer");
}

store("issuer", issuer);

const serverUrl = new URL("/mcp", issuer);

const provider: OAuthClientProvider = {
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
    store("state", state);

    return state;
  },
  clientInformation,
  saveClientInformation: (value) => {
    store("client", JSON.stringify(value));
  },
  tokens,
  saveTokens: (value) => {
    store("tokens", JSON.stringify(value));
  },
  saveCodeVerifier: (value) => {
    store("verifier", value);
  },
  codeVerifier: () => {
    const verifier = stored("verifier");

    if (verifier === undefined) {
      throw new Error("No code verifier was saved");
    }

    return verifier;
  },
  redirectToAuthorization: (url) => {
    store("authorizationUrl", url.href);
  },
};

let client: Client | undefined;

const connected = () => {
  if (client === undefined) {
    throw new Error("Not connected");
  }

  return client;
};

const mcpTest = {
  async inspectDiscovery() {
    const response = await fetch(serverUrl, { method: "POST" });

    const resource = await fetch(
      new URL("/.well-known/oauth-protected-resource", issuer)
    );

    const metadata: unknown = await resource.json();

    return {
      status: response.status,
      challenge: response.headers.get("www-authenticate"),
      resource: metadata,
    };
  },
  async connect() {
    client = new Client(
      { name: "browser-oauth-test", version: "1" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } }
    );

    const transport = new StreamableHTTPClientTransport(serverUrl, {
      authProvider: provider,
    });

    try {
      await client.connect(transport);

      return { connected: true };
    } catch (error) {
      const authorizationUrl = stored("authorizationUrl");

      if (authorizationUrl === undefined) {
        throw error;
      }

      return { authorizationUrl };
    }
  },
  async finishAuth() {
    const callback = new URLSearchParams(location.search);
    const state = callback.get("state");

    if (state === null || state === "" || state !== stored("state")) {
      throw new Error("OAuth callback state mismatch");
    }

    const exchange = new StreamableHTTPClientTransport(serverUrl, {
      authProvider: provider,
    });

    await exchange.finishAuth(callback);
    sessionStorage.removeItem("authorizationUrl");

    return { hasRefreshToken: tokens()?.refresh_token !== undefined };
  },
  async tools() {
    const { tools } = await connected().listTools();

    return tools.map((tool) => tool.name);
  },
  async createClient() {
    return await connected().callTool({
      name: "createClient",
      arguments: {
        client_name: "Created by browser MCP",
        redirect_uris: ["https://managed.example.internal/callback"],
        resources: [new URL("/", issuer).href],
        token_endpoint_auth_method: "none",
        application_type: "web",
      },
    });
  },
  async refresh() {
    const previous = tokens();
    const result = await auth(provider, { serverUrl });
    const current = tokens();

    return {
      result,
      rotated: previous?.refresh_token !== current?.refresh_token,
      hasAccessToken: current?.access_token !== undefined,
    };
  },
  close: async () => {
    await connected().close();
  },
};

declare global {
  interface Window {
    // why: the smoke drives the page through Playwright's `page.evaluate`
    mcpTest: typeof mcpTest;
  }
}

window.mcpTest = mcpTest;
