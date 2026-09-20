import { Schema } from "effect";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionGroup from "@gjermundgaraba/effect-actions/ActionGroup";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import { authenticationErrors, InvalidRequest } from "./errors.ts";

export const Actions = ActionGroup.make(
  { name: "browser", errors: [...authenticationErrors, InvalidRequest] },
  Action.make("login", {
    description: "Start an OAuth authorization-code flow with PKCE.",
    input: Schema.Struct({ returnTo: Schema.String }),
    success: Schema.Struct({ url: Schema.String }),
    mcp: false,
  }),
  Action.make("session", {
    description: "Read the current application session.",
    success: Schema.Struct({
      subject: Schema.String,
      scopes: Schema.Array(Schema.String),
      issuer: Schema.String,
    }),
    mcp: false,
  }),
  Action.make("logout", {
    description: "End this application session and revoke its refresh token.",
    success: Schema.Struct({}),
    mcp: false,
  }),
);

export const Http = ActionHttp.make({ apiPath: "/auth" }, Actions);
