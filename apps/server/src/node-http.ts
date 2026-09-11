import {
  createServer,
  type IncomingMessage,
  type RequestListener,
  type ServerResponse,
} from "node:http";

export const createNodeServer = (listener: RequestListener) =>
  createServer({ requestTimeout: 15000, headersTimeout: 10000 }, listener);

export function nodeListener(handler: (request: Request) => Promise<Response>, baseURL: string) {
  return async (incoming: IncomingMessage, outgoing: ServerResponse): Promise<void> => {
    try {
      if (!incoming.url?.startsWith("/") || incoming.url.startsWith("//")) {
        outgoing.writeHead(400).end();
        return;
      }
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (
          value &&
          !["forwarded", "x-forwarded-host", "x-forwarded-proto", "x-clankerauth-peer"].includes(
            name,
          )
        )
          headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      }
      // Rate limits use the direct socket peer. The proxy must enforce per-user/IP limits too.
      headers.set("x-clankerauth-peer", incoming.socket.remoteAddress ?? "unknown");
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of incoming) {
        size += chunk.length;
        if (size > 65536) {
          outgoing.writeHead(413).end();
          return;
        }
        chunks.push(chunk);
      }
      const response = await handler(
        new Request(`${baseURL}${incoming.url}`, {
          method: incoming.method,
          headers,
          body:
            incoming.method === "GET" || incoming.method === "HEAD"
              ? undefined
              : Buffer.concat(chunks),
        }),
      );
      const body = Buffer.from(await response.arrayBuffer());
      outgoing.writeHead(response.status, {
        ...Object.fromEntries(response.headers),
        "set-cookie": response.headers.getSetCookie(),
      });
      outgoing.end(body);
    } catch {
      if (outgoing.headersSent) outgoing.destroy();
      else outgoing.writeHead(500).end("Request failed");
    }
  };
}
