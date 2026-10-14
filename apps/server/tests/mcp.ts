import { Effect, Result } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import * as Testing from "@gjermundgaraba/effect-actions/Testing";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import { Administration } from "@clankerauth/admin-api";

interface WebMcpRequest {
  readonly method: string;
  readonly params?: ActionMcp.Params;
  readonly url: string;
  readonly headers?: Record<string, string>;
}

export const webMcpRequest = ({ method, params, url, headers }: WebMcpRequest) =>
  Result.getOrThrow(
    HttpClientRequest.toWebResult(ActionMcp.request(method, params, { url, headers })),
  );

export const administrationTools = (
  handler: (request: Request) => Promise<Response>,
  origin: string,
  token: string,
) =>
  ActionMcp.client(Administration, {
    url: `${origin}/mcp`,
    transformClient: HttpClient.mapRequest(HttpClientRequest.bearerToken(token)),
  }).pipe(Effect.provide(Testing.layer(handler)));

interface OfficialClientOptions {
  /** A web handler, such as `HttpRouter.toWebHandler(routes).handler`. */
  readonly fetch: (request: Request) => Promise<Response>;
  readonly path: string;
  readonly baseUrl: string;
  readonly headers: Record<string, string>;
}

export const withMcpClient = async <A>(
  { fetch, path, baseUrl, headers }: OfficialClientOptions,
  run: (client: Client) => Promise<A>,
): Promise<A> => {
  const client = new Client(
    { name: "test", version: "0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );

  try {
    await client.connect(
      new StreamableHTTPClientTransport(new URL(path, baseUrl), {
        fetch: (input, init) => fetch(new Request(input, init)),
        requestInit: { headers },
      }),
    );

    return await run(client);
  } finally {
    await client.close();
  }
};
