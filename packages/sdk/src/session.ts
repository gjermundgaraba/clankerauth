/**
 * The identity a browser page needs, without any verification code. This entry point is
 * browser-safe: it declares the identity a protected contract states, the `whoami` contract
 * and the issuer's sign-out URL, so contracts, bindings and pages import it directly, and a
 * server answers `Whoami` with its resource's `session`.
 */
import { Context, Schema } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import type { Principal as Verified } from "./verify.ts";

/**
 * Who calls, as `CurrentPrincipal` carries it: a verified credential's principal, the
 * `Verifier`'s, or on a trusted local surface the process itself, `actor: { kind: "local" }`,
 * which no verifier produces, with no `expiresAt`. Declared here, so a package declaring a
 * descriptor of `CurrentPrincipal` from this entry alone names it in its emitted declarations.
 */
export interface Caller extends Omit<Verified, "actor"> {
  readonly actor:
    | Verified["actor"]
    /** The process itself, on a trusted local surface: no credential was verified. */
    | { readonly kind: "local" };
}

/**
 * The caller: what a protected contract states, `caller: CurrentPrincipal`, and what an
 * authentication descriptor proves,
 * `Authentication.make("notes.Login", CurrentPrincipal, { error: ProviderUnavailable })`.
 * Remotely, the resource's provider gives it per request, from the verified credential; on
 * a trusted local surface, the host gives it the process, `Notes.local(subject)`.
 */
export class CurrentPrincipal extends Context.Service<CurrentPrincipal, Caller>()(
  "@clankerauth/CurrentPrincipal",
) {}

/** The verified credential behind a request, as the resource server read it. */
export const Principal = Schema.Struct({
  subject: Schema.NonEmptyString,
  issuer: Schema.NonEmptyString,
  scopes: Schema.Array(Schema.String),
});

export type Principal = typeof Principal.Type;

/**
 * The credential is a transport concern: a process surface has none, so bind `Whoami` to
 * HTTP alone, `ActionHttp.layer(Http, [app, Notes.session])`, and leave `Notes.session` out
 * of MCP.
 */
export const Whoami = Action.make("whoami", {
  description: "The verified subject, issuer and scopes behind this request's credential.",
  readOnly: true,
  caller: CurrentPrincipal,
  success: Principal,
});

/**
 * Sign out at the issuer, which ends its session and every app's forward cookie, then
 * return to `returnTo`. It is a plain link: any page under the cookie domain may use it.
 */
export const signOutUrl = (issuer: string, returnTo: string): string => {
  const url = new URL("/forward-auth/logout", issuer);
  url.searchParams.set("rd", returnTo);

  return url.href;
};
