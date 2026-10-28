import { Administration } from "@gjermundgaraba/clankerauth-admin-api";
import * as ActionMcp from "@gjermundgaraba/effect-actions/ActionMcp";
import * as Testing from "@gjermundgaraba/effect-actions/Testing";
import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { Effect, Result } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

interface WebMcpRequest {
  readonly method: string;
  readonly params?: ActionMcp.Params;
  readonly url: string;
  readonly headers?: Record<string, string>;
}

export const webMcpRequest = (request: WebMcpRequest) =>
  Result.getOrThrow(
    HttpClientRequest.toWebResult(
      ActionMcp.request(request.method, request.params, request)
    )
  );

export const administrationTools = (
  handler: (request: Request) => Promise<Response>,
  origin: string,
  token: string
) =>
  ActionMcp.client(Administration, {
    url: `${origin}/mcp`,
    transformClient: HttpClient.mapRequest(
      HttpClientRequest.bearerToken(token)
    ),
  }).pipe(Effect.provide(Testing.layer(handler)));

interface OfficialClientOptions {
  readonly fetch: (request: Request) => Promise<Response>;
  readonly path: string;
  readonly baseUrl: string;
  readonly headers: Record<string, string>;
}

export const withMcpClient = async <A>(
  { fetch, path, baseUrl, headers }: OfficialClientOptions,
  run: (client: Client) => Promise<A>
): Promise<A> => {
  const client = new Client(
    { name: "test", version: "0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } }
  );

  try {
    await client.connect(
      new StreamableHTTPClientTransport(new URL(path, baseUrl), {
        fetch: async (input, init) => await fetch(new Request(input, init)),
        requestInit: { headers },
      })
    );

    return await run(client);
  } finally {
    await client.close();
  }
};
