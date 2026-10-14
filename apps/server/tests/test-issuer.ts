import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Context, Effect, Layer, Option, Redacted, Scope } from "effect";
import { Cookies, HttpRouter, HttpServerRequest } from "effect/http";
import type { ClientMetadataResourceFetch } from "@better-auth/oauth-provider";
import { expect, vi } from "vite-plus/test";
import { application } from "../src/http/application.ts";
import { Settings, type IssuerSettings } from "../src/issuer/settings.ts";
import { CimdTransport } from "../src/platform/cimd-transport.ts";
import { peerHeader } from "../src/platform/node-http.ts";
import { issuerServices, type IssuerServices } from "../src/services.ts";

type SettingsOverrides = Partial<IssuerSettings> & Pick<IssuerSettings, "baseURL">;

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

export const issuerGeneration = (cimdTransport?: ClientMetadataResourceFetch) =>
  Layer.unwrap(
    Effect.map(Settings, (settings) =>
      issuerServices(Layer.succeed(Settings, settings), CimdTransport.layerWith(cimdTransport)),
    ),
  );

export const testIssuer = (
  overrides: SettingsOverrides,
  cimdTransport?: ClientMetadataResourceFetch,
) => issuerGeneration(cimdTransport).pipe(Layer.provideMerge(testSettings(overrides)));

export const startGeneration = (cimdTransport?: ClientMetadataResourceFetch) =>
  Effect.gen(function* () {
    // why: fibers forked into this scope start after the services, so closing it stops them first
    const scope = yield* Scope.fork(yield* Effect.scope, "sequential");
    const context = yield* Layer.buildWithScope(issuerGeneration(cimdTransport), scope);

    return { context, scope };
  });

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
                    // why: node-http sets the peer header from the socket; tests bypass node-http
                    request.modify({
                      remoteAddress: Option.fromNullishOr(request.headers[peerHeader]),
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

export const testWebApplication = (
  overrides: SettingsOverrides,
  cimdTransport?: ClientMetadataResourceFetch,
) => WebApplication.layer.pipe(Layer.provideMerge(testIssuer(overrides, cimdTransport)));

export const cookieHeader = (response: Response) =>
  Cookies.toCookieHeader(Cookies.fromSetCookie(response.headers.getSetCookie()));

export const cookieJar = () => {
  let cookies = Cookies.empty;

  return {
    header: () => Cookies.toCookieHeader(cookies),
    keep: (response: Response) => {
      cookies = Cookies.merge(cookies, Cookies.fromSetCookie(response.headers.getSetCookie()));
    },
    clear: () => {
      cookies = Cookies.empty;
    },
  };
};

export const signIn = (
  handle: (request: Request) => Promise<Response>,
  origin: string,
  credentials: { readonly email: string; readonly password: string },
) =>
  Effect.gen(function* () {
    const response = yield* Effect.promise(() =>
      handle(
        new Request(`${origin}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { origin, "content-type": "application/json", [peerHeader]: "127.0.0.1" },
          body: JSON.stringify(credentials),
        }),
      ),
    );

    expect(response.status, yield* Effect.promise(() => response.clone().text())).toBe(200);

    return cookieHeader(response);
  });

export const advanceDate = (millis: number) =>
  Effect.acquireRelease(
    Effect.sync(() => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(Date.now() + millis);
    }),
    () => Effect.sync(() => vi.useRealTimers()),
  );
