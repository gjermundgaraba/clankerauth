import { it } from "@effect/vitest";
import { expect } from "vite-plus/test";
import { Effect, Schema } from "effect";
import {
  InternalServerError,
  ProviderRefused,
  UnreadableRequest,
  type IssuerError,
} from "@clankerauth/admin-api";
import { APIError } from "better-auth/api";
import { HttpServerResponse } from "effect/http";
import { provider, refusal, respond } from "../src/issuer/errors.ts";
import { peerHeader } from "../src/platform/node-http.ts";
import { testWebApplication, WebApplication } from "./test-issuer.ts";

it("an internal failure keeps its cause for diagnostics and never puts it on the wire", () => {
  const cause = new Error("SQLITE_CORRUPT: database disk image is malformed");
  const failure = InternalServerError.of(cause);

  expect(failure.cause).toBe(cause);
  expect(Schema.encodeSync(InternalServerError)(failure)).toEqual(
    Schema.encodeSync(InternalServerError)(
      new InternalServerError({ message: "Request could not be completed" }),
    ),
  );
});

const baseURL = "http://localhost:3000";

/** Node requires `duplex` for a streaming request body; the DOM lib does not declare it. */
interface StreamingRequestInit extends RequestInit {
  readonly duplex: "half";
}

it.live("the provider bridge answers an unreadable body as a 400", () =>
  Effect.gen(function* () {
    const handle = yield* WebApplication;

    const init: StreamingRequestInit = {
      method: "POST",
      headers: {
        origin: baseURL,
        "content-type": "application/x-www-form-urlencoded",
        [peerHeader]: "127.0.0.1",
      },
      body: new ReadableStream({
        start: (controller) => controller.error(new Error("reset by peer")),
      }),
      duplex: "half",
    };

    const truncated = yield* Effect.promise(() =>
      handle(new Request(`${baseURL}/api/auth/oauth2/token`, init)),
    );

    expect(truncated.status).toBe(400);
    expect(yield* Effect.promise(() => truncated.json())).toEqual(
      Schema.encodeSync(UnreadableRequest)(
        new UnreadableRequest({ message: "Request body could not be read" }),
      ),
    );
  }).pipe(Effect.provide(testWebApplication({ baseURL }))),
);

it.effect("a provider status means only what its caller names; any other is internal", () =>
  Effect.gen(function* () {
    const refusedBy = (cause: unknown) =>
      Effect.flip(provider(() => Promise.reject(cause), { refused: refusal }));

    const answered = (failure: IssuerError) =>
      Effect.gen(function* () {
        const response = HttpServerResponse.toWeb(yield* respond(failure));

        return { status: response.status, body: yield* Effect.promise(() => response.json()) };
      });

    const internal = {
      status: 500,
      body: Schema.encodeSync(InternalServerError)(
        new InternalServerError({ message: "Request could not be completed" }),
      ),
    };

    expect(yield* answered(yield* refusedBy(new Error("SQLITE_BUSY")))).toEqual(internal);
    expect(
      yield* answered(yield* refusedBy(new APIError("BAD_REQUEST", { message: "Bad target" }))),
    ).toEqual({
      status: 400,
      body: Schema.encodeSync(ProviderRefused)(new ProviderRefused({ message: "Bad target" })),
    });

    for (const status of ["NOT_FOUND", "UNAUTHORIZED", "SERVICE_UNAVAILABLE"] as const) {
      expect(
        yield* answered(yield* refusedBy(new APIError(status, { message: "Not this caller's" }))),
      ).toEqual(internal);
    }
  }),
);
