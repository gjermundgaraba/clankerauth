import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Context, Effect, Layer, Option, Redacted, Scope } from "effect";
import { HttpRouter, HttpServerRequest } from "effect/http";
import { CurrentOwner } from "@clankerauth/admin-api";
import type { ClientMetadataResourceFetch } from "@better-auth/oauth-provider";
import { application } from "../src/http/application.ts";
import { Settings, type IssuerSettings } from "../src/issuer/settings.ts";
import { CimdTransport } from "../src/platform/cimd-transport.ts";
import { issuerServices, type IssuerServices } from "../src/services.ts";

type SettingsOverrides = Partial<IssuerSettings> & Pick<IssuerSettings, "baseURL">;

/**
 * Validated-shape settings on a fresh temporary database with one secret, so every generation
 * built on them opens the same issuer. The port follows the base URL unless overridden; the
 * directory is removed when the scope closes.
 */
export const testSettings = (overrides: SettingsOverrides) =>
  Layer.effect(
    Settings,
    Effect.acquireRelease(
      Effect.sync(() => mkdtempSync(join(tmpdir(), "clankerauth-test-"))),
      (directory) => Effect.sync(() => rmSync(directory, { recursive: true, force: true })),
    ).pipe(
      Effect.map((directory): IssuerSettings => ({
        secret: Redacted.make(randomBytes(32).toString("hex")),
        database: join(directory, "clankerauth.sqlite"),
        host: "127.0.0.1",
        port: Number(new URL(overrides.baseURL).port) || 3000,
        mcpAllowedOrigins: [],
        trustProxy: false,
        allowInsecureHttp: false,
        cookieDomain: undefined,
        ...overrides,
      })),
    ),
  );

const cimdLayer = (transport: ClientMetadataResourceFetch | undefined) =>
  transport === undefined
    ? CimdTransport.layer
    : Layer.succeed(CimdTransport, { fetch: transport });

/** One generation of the issuer's services on the settings in context. */
export const issuerGeneration = (cimdTransport?: ClientMetadataResourceFetch) =>
  Layer.unwrap(
    Effect.map(Settings, (settings) =>
      issuerServices(Layer.succeed(Settings, settings), cimdLayer(cimdTransport)),
    ),
  );

/** The issuer on a fresh temporary database, closed and removed with the test. */
export const testIssuer = (
  overrides: SettingsOverrides,
  cimdTransport?: ClientMetadataResourceFetch,
) => issuerGeneration(cimdTransport).pipe(Layer.provideMerge(testSettings(overrides)));

/**
 * A generation the test stops itself by closing `scope`. Fibers forked into `scope` start
 * after the services, so closing it interrupts and awaits them before the database closes,
 * in the order the server's own shutdown uses. The test's scope closes it otherwise.
 */
export const startGeneration = (cimdTransport?: ClientMetadataResourceFetch) =>
  Effect.gen(function* () {
    const scope = yield* Scope.fork(yield* Effect.scope, "sequential");
    const context = yield* Layer.buildWithScope(issuerGeneration(cimdTransport), scope);

    return { context, scope };
  });

/**
 * The issuer's web application as a fetch handler, disposed before the services it runs on.
 * Test boundary: the `x-clankerauth-peer` header simulates the socket peer, which production
 * never trusts.
 */
export class WebApplication extends Context.Service<
  WebApplication,
  (request: Request) => Promise<Response>
>()("test-issuer/WebApplication") {
  static readonly layer = Layer.effect(
    WebApplication,
    Effect.gen(function* () {
      const services = yield* Effect.context<IssuerServices>();

      const { handler } = yield* Effect.acquireRelease(
        Effect.sync(() =>
          HttpRouter.toWebHandler(
            application().pipe(Layer.provide(Layer.succeedContext(services))),
            {
              disableLogger: true,
              middleware: (effect) =>
                Effect.flatMap(HttpServerRequest.HttpServerRequest, (request) =>
                  Effect.provideService(
                    effect,
                    HttpServerRequest.HttpServerRequest,
                    request.modify({
                      remoteAddress: Option.fromNullishOr(request.headers["x-clankerauth-peer"]),
                    }),
                  ),
                ),
            },
          ),
        ),
        ({ dispose }) => Effect.promise(dispose),
      );

      return handler;
    }),
  );
}

/** `testIssuer` with its web application. */
export const testWebApplication = (
  overrides: SettingsOverrides,
  cimdTransport?: ClientMetadataResourceFetch,
) => WebApplication.layer.pipe(Layer.provideMerge(testIssuer(overrides, cimdTransport)));

/** Act as the owner whose provider session these headers carry, as the dashboard does. */
export const withOwnerHeaders =
  (headers: Headers) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>) =>
    effect.pipe(
      Effect.provideService(CurrentOwner, {
        userId: "",
        email: "",
        writable: true,
        providerHeaders: Effect.succeed(headers),
      }),
      Effect.scoped,
    );
