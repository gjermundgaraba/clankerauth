export * as Resource from "./resource.ts";

// The same types by a flat name: a consumer's emitted declarations name a type through an
// entry point's own exports, not through the `Resource` namespace, so an exported resource,
// or an implementation stating its authorizer, needs each of these reachable as itself.
export type {
  Admission,
  Built as BuiltResource,
  Declaration as ResourceDeclaration,
  Declared as DeclaredResource,
  Login,
  Options as ResourceOptions,
  Refusal,
  Resource as ResourceService,
} from "./resource.ts";

export type { Principal, Verifier } from "./verify.ts";
