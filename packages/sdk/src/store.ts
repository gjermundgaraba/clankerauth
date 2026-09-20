import { Context, Effect } from "effect";
import type { StoreError } from "./errors.ts";

export interface Row {
  readonly payload: string;
  readonly expires: number;
}

/** Sealed rows. One process owns a store; the session capability serializes work per id. */
export class SessionStore extends Context.Service<
  SessionStore,
  {
    readonly get: (id: string) => Effect.Effect<Row | undefined, StoreError>;
    readonly put: (id: string, payload: string, expires: number) => Effect.Effect<void, StoreError>;
    readonly delete: (id: string) => Effect.Effect<void, StoreError>;
    readonly sweep: (now: number) => Effect.Effect<void, StoreError>;
  }
>()("@clankerauth/SessionStore") {}
