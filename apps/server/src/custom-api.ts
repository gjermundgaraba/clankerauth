import { Effect, Layer } from "effect";
import { NodeHttpServer } from "@effect/platform-node";
import { HttpRouter, HttpServerRequest } from "effect/unstable/http";
import { HttpApiBuilder, HttpApiMiddleware } from "effect/unstable/httpapi";
import {
  Api,
  ApiValidation,
  InternalServerError,
  BadRequest,
  CurrentOwner,
  Forbidden,
  OwnerAuthorization,
  SetupProtection,
} from "@clankerauth/api";
import { machineKeys } from "./machine-keys.ts";
import { administration } from "./administration.ts";
import type { Service } from "./auth.ts";

export function customApi(service: Service) {
  const admin = administration(service);
  const keys = machineKeys(service);
  const ownerAuthorization = Layer.succeed(OwnerAuthorization, (httpEffect) =>
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const session = yield* admin.requireOwner(
        new Headers(request.headers),
        request.method !== "GET",
      );
      return yield* Effect.provideService(httpEffect, CurrentOwner, {
        userId: session.user.id,
        email: session.user.email,
      });
    }),
  );
  const setupProtection = Layer.succeed(SetupProtection, (httpEffect) =>
    Effect.gen(function* () {
      const request = yield* HttpServerRequest.HttpServerRequest;
      if (request.headers.origin !== service.settings.baseURL)
        return yield* Effect.fail(new Forbidden({ error: "Invalid origin" }));
      if (
        request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase() !== "application/json"
      )
        return yield* Effect.fail(new BadRequest({ error: "JSON required" }));
      return yield* httpEffect;
    }),
  );
  const setup = HttpApiBuilder.group(Api, "setup", (handlers) =>
    handlers
      .handle("status", () =>
        service.owner().pipe(
          Effect.map((owner) => ({ required: !owner })),
          Effect.mapError(
            () => new InternalServerError({ error: "Request could not be completed" }),
          ),
        ),
      )
      .handle("create", ({ payload }) => admin.setup(payload)),
  );
  const clients = HttpApiBuilder.group(Api, "clients", (handlers) =>
    handlers
      .handle("list", ({ request }) =>
        Effect.flatMap(CurrentOwner, (owner) =>
          admin.list(new Headers(request.headers), owner.email),
        ),
      )
      .handle("create", ({ request, payload }) =>
        admin.create(new Headers(request.headers), payload),
      )
      .handle("delete", ({ request, payload }) =>
        admin.delete(new Headers(request.headers), payload),
      )
      .handle("revoke", ({ payload }) => admin.revoke(payload))
      .handle("block", ({ payload }) => admin.block(payload))
      .handle("rotate", ({ request, payload }) =>
        admin.rotate(new Headers(request.headers), payload),
      )
      .handle("access", ({ payload, request }) =>
        admin.access(new Headers(request.headers), payload),
      ),
  );
  const resources = HttpApiBuilder.group(Api, "resources", (handlers) =>
    handlers
      .handle("create", ({ payload, request }) =>
        admin.createResource(new Headers(request.headers), payload),
      )
      .handle("update", ({ payload, request }) =>
        admin.updateResource(new Headers(request.headers), payload),
      )
      .handle("delete", ({ payload, request }) =>
        admin.deleteResource(new Headers(request.headers), payload),
      ),
  );
  const apiKeys = HttpApiBuilder.group(Api, "apiKeys", (handlers) =>
    handlers
      .handle("list", ({ request }) => keys.list(new Headers(request.headers)))
      .handle("create", ({ payload }) => keys.create(payload))
      .handle("update", ({ payload }) => keys.update(payload))
      .handle("delete", ({ request, payload }) =>
        keys.delete(new Headers(request.headers), payload.keyId),
      ),
  );
  const verification = HttpApiBuilder.group(Api, "keyVerification", (handlers) =>
    handlers.handle("verify", ({ request, payload }) =>
      keys.verify(new Headers(request.headers), payload.resource),
    ),
  );
  const validation = HttpApiMiddleware.layerSchemaErrorTransform(ApiValidation, (error) =>
    Effect.fail(
      error.kind === "Body" || error.kind === "ResponseHeaders"
        ? new InternalServerError({ error: "Request could not be completed" })
        : new BadRequest({ error: "Invalid request" }),
    ),
  );
  const routes = HttpApiBuilder.layer(Api).pipe(
    Layer.provide([setup, clients, resources, apiKeys, verification]),
    Layer.provide([ownerAuthorization, setupProtection, validation]),
    Layer.provide(NodeHttpServer.layerHttpServices),
  );
  return HttpRouter.toWebHandler(routes, { disableLogger: true });
}
