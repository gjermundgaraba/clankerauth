import { Effect, Result } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import * as Testing from "@gjermundgaraba/effect-actions/Testing";
import { Administration } from "@clankerauth/admin-api";

interface WebMcpRequest {
  readonly method: string;
  readonly params?: Testing.McpParams;
  readonly url: string;
  readonly headers?: Record<string, string>;
}

/** `Testing.mcpRequest` as a web `Request`, for a test to hand to a handler or to `fetch`. */
export const webMcpRequest = ({ method, params, url, headers }: WebMcpRequest) =>
  Result.getOrThrow(
    HttpClientRequest.toWebResult(Testing.mcpRequest(method, params, { url, headers })),
  );

/** The administration tools of `handler`'s `/mcp`, called as `token`'s owner. */
export const administrationTools = (
  handler: (request: Request) => Promise<Response>,
  origin: string,
  token: string,
) =>
  Effect.runPromise(
    Testing.mcpClient(Administration, {
      url: `${origin}/mcp`,
      transformClient: HttpClient.mapRequest(HttpClientRequest.bearerToken(token)),
    }).pipe(Effect.provide(Testing.layer(handler))),
  );

interface OfficialClientOptions {
  /** A web handler, such as `HttpRouter.toWebHandler(routes).handler`. */
  readonly fetch: (request: Request) => Promise<Response>;
  readonly path: string;
  readonly baseUrl: string;
  readonly headers: Record<string, string>;
}

/**
 * Connect an official client pinned to MCP 2026-07-28, the revision the endpoint serves,
 * and always close its transport after the callback.
 */
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
