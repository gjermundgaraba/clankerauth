import { expect, test } from "vite-plus/test";
import { Effect, Schema } from "effect";
import { BadRequest, InternalServerError } from "@clankerauth/admin-api";
import { APIError } from "better-auth/api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import { HttpServerResponse } from "effect/http";
import { internalError, respond } from "../src/api-errors.ts";
import { openIssuer } from "./issuer.ts";
import { webApplication } from "./web-application.ts";

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

test("a route's own failures keep their bodies, and a provider refusal is the built-in 403", async () => {
  // What `/forward-auth*` and `/healthz` answer a failure with: `respond`.
  const answered = async (cause: unknown) => {
    const response = HttpServerResponse.toWeb(await Effect.runPromise(respond(cause)));

    return { status: response.status, body: await response.json() };
  };

  // The issuer's own vocabulary is unchanged: `error`, under its tag.
  expect(await answered(new Error("SQLITE_BUSY"))).toEqual({
    status: 500,
    body: Schema.encodeSync(InternalServerError)(
      new InternalServerError({ error: "Request could not be completed" }),
    ),
  });
  expect(await answered(new APIError("BAD_REQUEST", { message: "Bad target" }))).toEqual({
    status: 400,
    body: Schema.encodeSync(BadRequest)(new BadRequest({ error: "Bad target" })),
  });

  // A provider 401 or 403 is effect-actions' `Forbidden`, which carries `message`.
  for (const status of ["UNAUTHORIZED", "FORBIDDEN"] as const) {
    expect(await answered(new APIError(status, { message: "Not the owner" }))).toEqual({
      status: 403,
      body: Schema.encodeSync(Action.Forbidden)(new Action.Forbidden({ message: "Not the owner" })),
    });
  }
});
