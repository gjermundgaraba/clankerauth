import { Tips } from "@gjermundgaraba-designs/pixel-paper";
import { Schema } from "effect";
import { defineMessageUnion } from "foldkit/message";
import { UrlRequest } from "foldkit/navigation";
import { Url } from "foldkit/url";

import { Access } from "./model.ts";
import * as Consent from "./page/consent.ts";
import * as Dashboard from "./page/dashboard/index.ts";
import * as Login from "./page/login.ts";
import * as Setup from "./page/setup.ts";

export const Message = defineMessageUnion({
  SucceededCheckAccess: { access: Access },
  FailedCheckAccess: { reason: Schema.String },
  ClickedRetryAccess: {},
  ClickedLink: { request: UrlRequest },
  ChangedUrl: { url: Url },
  CompletedNavigateInternal: {},
  CompletedReplaceUrl: {},
  CompletedLoadUrl: {},
  CompletedReloadPage: {},
  CompletedScrollToFragment: {},
  GotSetupMessage: { message: Setup.Message },
  GotLoginMessage: { message: Login.Message },
  GotConsentMessage: { message: Consent.Message },
  GotDashboardMessage: { message: Dashboard.Message },
  GotTipsMessage: { message: Tips.Message },
});

export type Message = typeof Message.Type;
