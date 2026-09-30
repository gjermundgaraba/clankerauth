import { Duration } from "effect";

/**
 * How long a key list answers the keys it names before it is read again: the delay after
 * which a revoked, disabled or re-scoped key loses what it had, and how often a watched
 * connection's key is checked again. Internal: not a package entry point.
 */
export const keyListRefresh = Duration.minutes(1);
