import { it } from "@effect/vitest";
import { expect } from "vite-plus/test";
import { Effect, Schema } from "effect";
import { InternalServerError, ProviderRefused, UnreadableRequest } from "@clankerauth/admin-api";
import { APIError } from "better-auth/api";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import { HttpServerResponse } from "effect/http";
import { provider, respond } from "../src/issuer/errors.ts";
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
        "x-clankerauth-peer": "127.0.0.1",
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

it.effect(
  "a route's own failures keep their bodies, and a provider refusal is the built-in 403",
  () =>
    Effect.gen(function* () {
      // What `/forward-auth*` and `/healthz` answer a failure with: `respond`.
      const answered = (cause: unknown) =>
        Effect.gen(function* () {
          // A provider call fails as `provider` turns what the provider threw.
          const failure = yield* Effect.flip(provider(() => Promise.reject(cause)));
          const response = HttpServerResponse.toWeb(yield* respond(failure));

          return { status: response.status, body: yield* Effect.promise(() => response.json()) };
        });

      // The issuer's own failures carry `message` under their tag.
      expect(yield* answered(new Error("SQLITE_BUSY"))).toEqual({
        status: 500,
        body: Schema.encodeSync(InternalServerError)(
          new InternalServerError({ message: "Request could not be completed" }),
        ),
      });
      expect(yield* answered(new APIError("BAD_REQUEST", { message: "Bad target" }))).toEqual({
        status: 400,
        body: Schema.encodeSync(ProviderRefused)(new ProviderRefused({ message: "Bad target" })),
      });

      // A provider 401 or 403 is effect-actions' `Forbidden`, which carries `message`.
      for (const status of ["UNAUTHORIZED", "FORBIDDEN"] as const) {
        expect(yield* answered(new APIError(status, { message: "Not the owner" }))).toEqual({
          status: 403,
          body: Schema.encodeSync(Action.Forbidden)(
            new Action.Forbidden({ message: "Not the owner" }),
          ),
        });
      }
    }),
);
