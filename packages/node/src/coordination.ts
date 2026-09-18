import { Effect, Semaphore } from "effect";

/** Reference counts include waiters, so an interrupted waiter cannot split a live lock. */
export const make = Effect.sync(() => {
  const entries = new Map<string, { semaphore: Semaphore.Semaphore; users: number }>();

  return <A, E, R>(id: string, action: Effect.Effect<A, E, R>) =>
    Effect.acquireUseRelease(
      Effect.sync(() => {
        let entry = entries.get(id);

        if (!entry) {
          entry = { semaphore: Semaphore.makeUnsafe(1), users: 0 };
          entries.set(id, entry);
        }

        entry.users++;

        return entry;
      }),
      (entry) => entry.semaphore.withPermit(action),
      (entry) =>
        Effect.sync(() => {
          entry.users--;

          if (entry.users === 0) entries.delete(id);
        }),
    );
});
