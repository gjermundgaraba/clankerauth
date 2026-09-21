/**
 * The identity a browser page needs, without any verification code. This entry point is
 * browser-safe: it declares the `session` contract and builds the issuer's sign-out URL,
 * so a page imports it directly and a server answers it with `resource.session`.
 */
import { Schema } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionGroup from "@gjermundgaraba/effect-actions/ActionGroup";

/** The verified credential behind a request, as the resource server read it. */
export const Principal = Schema.Struct({
  subject: Schema.NonEmptyString,
  issuer: Schema.NonEmptyString,
  scopes: Schema.Array(Schema.String),
});

export type Principal = typeof Principal.Type;

/**
 * The credential is a transport concern: a process surface has none, so `whoami` is its
 * own group and never an MCP tool. Bind it with `Http.layer(app, resource.session)`.
 */
export const Session = ActionGroup.make(
  { name: "session" },
  Action.make("whoami", {
    description: "The verified subject, issuer and scopes behind this request's credential.",
    access: "read",
    success: Principal,
    mcp: false,
  }),
);

/**
 * Sign out at the issuer, which ends its session and every app's forward cookie, then
 * return to `returnTo`. It is a plain link: any page under the cookie domain may use it.
 */
export const signOutUrl = (issuer: string, returnTo: string): string => {
  const url = new URL("/forward-auth/logout", issuer);
  url.searchParams.set("rd", returnTo);

  return url.href;
};
