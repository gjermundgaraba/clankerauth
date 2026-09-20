export * as Verifier from "./verify.ts";

export type { Principal } from "./verify.ts";

export {
  Unauthorized,
  Forbidden,
  RateLimited,
  ProviderUnavailable,
  ConfigurationError,
  type AuthenticationError,
} from "./errors.ts";
