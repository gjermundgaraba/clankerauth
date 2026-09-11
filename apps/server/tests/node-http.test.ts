import { afterEach, expect, test, vi } from "vite-plus/test";
import { request, type RequestListener, type Server } from "node:http";
import { createNodeServer, nodeListener } from "../src/node-http.ts";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeAllConnections();
        }),
    ),
  );
});
async function listen(listener: RequestListener) {
  const server = createNodeServer(listener);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected a TCP listener");
  return { server, url: `http://127.0.0.1:${address.port}` };
}
const rawRequest = (url: string, path: string) =>
  new Promise<number | undefined>((resolve, reject) => {
    const req = request(url, { path }, (res) => {
      res.on("error", reject);
      res.on("end", () => resolve(res.statusCode));
      res.resume();
    });
    req.on("error", reject);
    req.end();
  });

test("canonical request URL, trusted peer, body and multiple cookies survive the bridge", async () => {
  const handler = vi.fn(async (req: Request) => {
    expect(req.url).toBe("https://issuer.example/path?query=value");
    expect(req.method).toBe("POST");
    expect(await req.text()).toBe("payload");
    for (const name of ["forwarded", "x-forwarded-host", "x-forwarded-proto"])
      expect(req.headers.has(name)).toBe(false);
    expect(req.headers.get("x-clankerauth-peer")).toBe("127.0.0.1");
    expect(req.headers.get("cookie")).toBe("session=owner");
    return new Response("created", {
      status: 201,
      headers: [
        ["set-cookie", "a=1"],
        ["set-cookie", "b=2"],
      ],
    });
  });
  const { server, url } = await listen(nodeListener(handler, "https://issuer.example"));
  expect(server.requestTimeout).toBe(15000);
  expect(server.headersTimeout).toBe(10000);
  const response = await fetch(`${url}/path?query=value`, {
    method: "POST",
    headers: {
      host: "evil.example",
      forwarded: "for=evil",
      "x-forwarded-host": "evil.example",
      "x-forwarded-proto": "http",
      "x-clankerauth-peer": "forged",
      cookie: "session=owner",
    },
    body: "payload",
  });
  expect(response.status).toBe(201);
  expect(response.headers.getSetCookie()).toEqual(["a=1", "b=2"]);
  expect(await response.text()).toBe("created");
  expect(handler).toHaveBeenCalledTimes(1);
});

test.each(["GET", "HEAD"])("%s has no Fetch request body", async (method) => {
  const handler = vi.fn(async (req: Request) => {
    expect(req.method).toBe(method);
    expect(req.body).toBeNull();
    return new Response("ok");
  });
  const { url } = await listen(nodeListener(handler, "https://issuer.example"));
  const response = await fetch(url, { method });
  expect(response.status).toBe(200);
  expect(await response.text()).toBe(method === "HEAD" ? "" : "ok");
  expect(handler).toHaveBeenCalledTimes(1);
});

test("rejects non-origin request targets before calling the handler", async () => {
  const handler = vi.fn(async () => new Response("unexpected"));
  const { url } = await listen(nodeListener(handler, "https://issuer.example"));
  for (const path of ["//evil.example/path", "http://evil.example/path", "*"])
    expect(await rawRequest(url, path)).toBe(400);
  expect(handler).not.toHaveBeenCalled();
});

test("accepts exactly 64 KiB and rejects larger bodies", async () => {
  const handler = vi.fn(
    async (req: Request) => new Response(String((await req.arrayBuffer()).byteLength)),
  );
  const { url } = await listen(nodeListener(handler, "https://issuer.example"));
  const accepted = await fetch(url, { method: "POST", body: "x".repeat(65536) });
  expect(accepted.status).toBe(200);
  expect(await accepted.text()).toBe("65536");
  const rejected = await fetch(url, { method: "POST", body: "x".repeat(65537) });
  expect(rejected.status).toBe(413);
  await rejected.body?.cancel();
  expect(handler).toHaveBeenCalledTimes(1);
});

test.each(["handler", "body"])(
  "%s failure returns a generic 500 before committing response headers",
  async (failure) => {
    const { url } = await listen(
      nodeListener(async () => {
        if (failure === "handler") throw new Error("private failure details");
        return new Response(
          new ReadableStream({
            start(controller) {
              controller.error(new Error("private failure details"));
            },
          }),
          { status: 201, headers: { "x-private": "secret" } },
        );
      }, "https://issuer.example"),
    );
    const response = await fetch(url);
    expect(response.status).toBe(500);
    expect(response.headers.has("x-private")).toBe(false);
    expect(await response.text()).toBe("Request failed");
  },
);

test("failure after headers are committed aborts the response instead of writing another status", async () => {
  const adapter = nodeListener(async () => {
    throw new Error("transport failure");
  }, "https://issuer.example");
  const { url } = await listen((incoming, outgoing) => {
    outgoing.writeHead(200);
    outgoing.flushHeaders();
    void adapter(incoming, outgoing);
  });
  await expect(rawRequest(url, "/")).rejects.toThrow();
});
