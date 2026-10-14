import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Context, Effect, Exit, Fiber, Layer, Redacted, Scope } from "effect";
import { CurrentOwner } from "@clankerauth/admin-api";
import type { ClientMetadataResourceFetch } from "@better-auth/oauth-provider";
import { Settings, type IssuerSettings } from "../src/issuer/settings.ts";
import { CimdTransport } from "../src/platform/cimd-transport.ts";
import { issuerServices, type IssuerServices } from "../src/services.ts";

/** Validated-shape settings for tests; the port follows the base URL unless overridden. */
const testSettings = (
  directory: string,
  overrides: Partial<IssuerSettings> & Pick<IssuerSettings, "baseURL">,
): IssuerSettings => ({
  secret: Redacted.make(randomBytes(32).toString("hex")),
  database: join(directory, "clankerauth.sqlite"),
  host: "127.0.0.1",
  port: Number(new URL(overrides.baseURL).port) || 3000,
  mcpAllowedOrigins: [],
  trustProxy: false,
  allowInsecureHttp: false,
  cookieDomain: undefined,
  ...overrides,
});

/**
 * One opened issuer: its services built into a sequential scope the test owns. Fibers
 * run in that scope after the services, so stopping interrupts and awaits them before the
 * database closes, in the order the server's own shutdown uses.
 */
export interface OpenedIssuer {
  readonly settings: IssuerSettings;
  readonly context: Context.Context<IssuerServices>;
  /** One of the issuer's services. */
  readonly get: <I extends IssuerServices, S>(tag: Context.Key<I, S>) => S;
  /** Run Effects with the issuer's services in context. */
  readonly run: <A, E>(effect: Effect.Effect<A, E, IssuerServices>) => Promise<A>;
  readonly runExit: <A, E>(effect: Effect.Effect<A, E, IssuerServices>) => Promise<Exit.Exit<A, E>>;
  readonly runFork: <A, E>(effect: Effect.Effect<A, E, IssuerServices>) => Fiber.Fiber<A, E>;
  /** Shuts the issuer down. Idempotent. */
  readonly stop: () => Promise<void>;
  /** Stops this generation and opens another on the same database and secret. */
  readonly reopen: () => Promise<OpenedIssuer>;
  /** Stops the issuer and removes its temporary database directory. */
  readonly close: () => Promise<void>;
}

const cimdLayer = (transport: ClientMetadataResourceFetch | undefined) =>
  transport === undefined
    ? CimdTransport.layer
    : Layer.succeed(CimdTransport, { fetch: transport });

const openGeneration = async (
  directory: string,
  settings: IssuerSettings,
  cimdTransport: ClientMetadataResourceFetch | undefined,
): Promise<OpenedIssuer> => {
  const scope = Scope.makeUnsafe();

  const context = await Effect.runPromise(
    Effect.provideService(
      Layer.build(issuerServices(Layer.succeed(Settings, settings), cimdLayer(cimdTransport))),
      Scope.Scope,
      scope,
    ),
  );

  const runFork = <A, E>(effect: Effect.Effect<A, E, IssuerServices>) =>
    Effect.runForkWith(context)(effect, { onFiberStart: Fiber.runIn(scope) });

  const stop = () => Effect.runPromise(Scope.close(scope, Exit.void));

  return {
    settings,
    context,
    get: (tag) => Context.get(context, tag),
    run: (effect) => Effect.runPromise(Fiber.join(runFork(effect))),
    runExit: (effect) => Effect.runPromise(Fiber.await(runFork(effect))),
    runFork,
    stop,
    reopen: async () => {
      await stop();

      return openGeneration(directory, settings, cimdTransport);
    },
    close: async () => {
      await stop();
      rmSync(directory, { recursive: true, force: true });
    },
  };
};

/** Opens an issuer on a fresh temporary database. */
export const openIssuer = (
  overrides: Partial<IssuerSettings> & Pick<IssuerSettings, "baseURL">,
  cimdTransport?: ClientMetadataResourceFetch,
): Promise<OpenedIssuer> => {
  const directory = mkdtempSync(join(tmpdir(), "clankerauth-test-"));

  return openGeneration(directory, testSettings(directory, overrides), cimdTransport);
};

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
