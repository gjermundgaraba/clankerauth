import { Duration } from "effect";

/**
 * How long a key list answers verification before it is read again: the delay after
 * which a revoked, disabled, expired or re-scoped key is refused, and how often a watched
 * connection's key is checked again. Internal: not a package entry point.
 */
export const keyListRefresh = Duration.minutes(1);
