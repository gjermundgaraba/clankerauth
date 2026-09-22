import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Context, Effect, Exit, Fiber, Layer, Redacted, Scope } from "effect";
import { Auth, type Integrations } from "../src/auth.ts";
import type { Settings } from "../src/config.ts";

/** Validated-shape settings for tests; the port follows the base URL unless overridden. */
const testSettings = (
  directory: string,
  overrides: Partial<Settings> & Pick<Settings, "baseURL">,
): Settings => ({
  secret: Redacted.make(randomBytes(32).toString("hex")),
  database: join(directory, "auth.sqlite"),
  host: "127.0.0.1",
  port: Number(new URL(overrides.baseURL).port) || 3000,
  mcpAllowedOrigins: [],
  trustProxy: false,
  allowInsecureHttp: false,
  cookieDomain: undefined,
  ...overrides,
});

/**
 * One opened issuer: `Auth.layer` built into a sequential scope the test owns. Fibers
 * run in that scope after the layer, so stopping interrupts and awaits them before the
 * database closes, in the order the server's own shutdown uses.
 */
export interface Issuer {
  readonly settings: Settings;
  readonly service: Auth["Service"];
  /** Run Effects with the issuer in context. */
  readonly run: <A, E>(effect: Effect.Effect<A, E, Auth>) => Promise<A>;
  readonly runExit: <A, E>(effect: Effect.Effect<A, E, Auth>) => Promise<Exit.Exit<A, E>>;
  readonly runFork: <A, E>(effect: Effect.Effect<A, E, Auth>) => Fiber.Fiber<A, E>;
  /** Shuts the issuer down. Idempotent. */
  readonly stop: () => Promise<void>;
  /** Stops this generation and opens another on the same database and secret. */
  readonly reopen: () => Promise<Issuer>;
  /** Stops the issuer and removes its temporary database directory. */
  readonly close: () => Promise<void>;
}

const openGeneration = async (
  directory: string,
  settings: Settings,
  integrations: Integrations,
): Promise<Issuer> => {
  const scope = Scope.makeUnsafe();

  const context = await Effect.runPromise(
    Effect.provideService(Layer.build(Auth.layer(settings, integrations)), Scope.Scope, scope),
  );

  const runFork = <A, E>(effect: Effect.Effect<A, E, Auth>) =>
    Effect.runForkWith(context)(effect, { onFiberStart: Fiber.runIn(scope) });

  const stop = () => Effect.runPromise(Scope.close(scope, Exit.void));

  return {
    settings,
    service: Context.get(context, Auth),
    run: (effect) => Effect.runPromise(Fiber.join(runFork(effect))),
    runExit: (effect) => Effect.runPromise(Fiber.await(runFork(effect))),
    runFork,
    stop,
    reopen: async () => {
      await stop();

      return openGeneration(directory, settings, integrations);
    },
    close: async () => {
      await stop();
      rmSync(directory, { recursive: true, force: true });
    },
  };
};

/** Opens an issuer on a fresh temporary database. */
export const openIssuer = (
  overrides: Partial<Settings> & Pick<Settings, "baseURL">,
  integrations: Integrations = {},
): Promise<Issuer> => {
  const directory = mkdtempSync(join(tmpdir(), "clankerauth-test-"));

  return openGeneration(directory, testSettings(directory, overrides), integrations);
};
