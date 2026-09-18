import assert from "node:assert/strict";
import { test } from "vite-plus/test";
import { Deferred, Effect, Fiber } from "effect";
import * as Coordination from "../src/coordination.ts";
import { run } from "./support.ts";

test("interrupted lock owners and waiters release admission without splitting the lock", () =>
  run(
    Effect.gen(function* () {
      const locked = yield* Coordination.make;
      const entered = yield* Deferred.make<void>();

      const owner = yield* locked(
        "session",
        Effect.gen(function* () {
          yield* Deferred.succeed(entered, undefined);
          yield* Effect.never;
        }),
      ).pipe(Effect.forkChild);

      yield* Deferred.await(entered);

      let waiterEntered = false;

      const waiter = yield* locked(
        "session",
        Effect.sync(() => {
          waiterEntered = true;
        }),
      ).pipe(Effect.forkChild);

      yield* Effect.yieldNow;
      yield* Fiber.interrupt(waiter);
      assert.equal(waiterEntered, false);
      // A cancelled waiter must not remove the still-owned entry from the map.
      let replacementEntered = false;

      const replacement = yield* locked(
        "session",
        Effect.sync(() => {
          replacementEntered = true;
        }),
      ).pipe(Effect.forkChild);

      yield* Effect.yieldNow;
      assert.equal(replacementEntered, false);
      yield* Fiber.interrupt(owner);
      yield* Fiber.join(replacement);
      assert.equal(replacementEntered, true);
      assert.equal(yield* locked("session", Effect.succeed("released")), "released");
    }),
  ));

test("different sessions do not block one another", () =>
  run(
    Effect.gen(function* () {
      const locked = yield* Coordination.make;
      const entered = yield* Deferred.make<void>();

      const owner = yield* locked(
        "first",
        Effect.gen(function* () {
          yield* Deferred.succeed(entered, undefined);
          yield* Effect.never;
        }),
      ).pipe(Effect.forkChild);

      yield* Deferred.await(entered);
      assert.equal(yield* locked("second", Effect.succeed("independent")), "independent");
      yield* Fiber.interrupt(owner);
    }),
  ));
