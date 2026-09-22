import { expect, test } from "vite-plus/test";
import { Schema } from "effect";
import { BadRequest, InternalServerError } from "@clankerauth/admin-api";
import { internalError } from "../src/api-errors.ts";
import { openIssuer } from "./issuer.ts";
import { webApplication } from "./web-application.ts";

test("encoded error expectations preserve exact wire assertions", async () => {
  const expected = Schema.encodeSync(InternalServerError)(
    new InternalServerError({ error: "Request could not be completed" }),
  );

  expect(Object.keys(expected).sort()).toEqual(["_tag", "error"]);

  const response = Response.json({ ...expected, secret: "must not escape" });
  const actual = await response.json();

  // Decoding the actual response would erase the leak and weaken this assertion.
  expect(actual).not.toEqual(expected);
  expect(
    Schema.encodeSync(InternalServerError)(Schema.decodeUnknownSync(InternalServerError)(actual)),
  ).toEqual(expected);
});

test("an internal failure keeps its cause for diagnostics and never puts it on the wire", () => {
  const cause = new Error("SQLITE_CORRUPT: database disk image is malformed");
  const failure = internalError(cause);

  expect(failure.cause).toBe(cause);
  expect(Schema.encodeSync(InternalServerError)(failure)).toEqual(
    Schema.encodeSync(InternalServerError)(
      new InternalServerError({ error: "Request could not be completed" }),
    ),
  );
});

test("BadRequest wire expectations contain only the public error contract", () => {
  const expected = Schema.encodeSync(BadRequest)(new BadRequest({ error: "Invalid request" }));

  expect(Object.keys(expected).sort()).toEqual(["_tag", "error"]);
  expect(expected.error).toBe("Invalid request");
});

/** Node requires `duplex` for a streaming request body; the DOM lib does not declare it. */
interface StreamingRequestInit extends RequestInit {
  readonly duplex: "half";
}

test("the provider bridge answers an unreadable body as a 400", async () => {
  const baseURL = "http://localhost:3000";
  const issuer = await openIssuer({ baseURL });

  const handle = webApplication(issuer.service);

  const post = (body: BodyInit) => {
    const init: StreamingRequestInit = {
      method: "POST",
      headers: {
        origin: baseURL,
        "content-type": "application/x-www-form-urlencoded",
        "x-clankerauth-peer": "127.0.0.1",
      },
      body,
      duplex: "half",
    };

    return handle(new Request(`${baseURL}/api/auth/oauth2/token`, init));
  };

  try {
    const truncated = await post(
      new ReadableStream({ start: (controller) => controller.error(new Error("reset by peer")) }),
    );

    expect(truncated.status).toBe(400);
    expect(await truncated.json()).toEqual(
      Schema.encodeSync(BadRequest)(new BadRequest({ error: "Request body could not be read" })),
    );
  } finally {
    await handle.dispose();
    await issuer.close();
  }
});
