import { Tips } from "@gjermundgaraba-designs/pixel-paper";
import { Schema } from "effect";
import { defineTaggedUnion } from "foldkit/schema";
import { Url } from "foldkit/url";

import * as Consent from "./page/consent.ts";
import * as Dashboard from "./page/dashboard/index.ts";
import * as Login from "./page/login.ts";
import * as Setup from "./page/setup.ts";
import { urlToAppRoute } from "./route.ts";
import type { AppRoute } from "./route.ts";

export const Access = defineTaggedUnion({
  SetupRequired: {},
  SignedIn: {},
  SignedOut: {},
});

export type Access = typeof Access.Type;

export const Page = defineTaggedUnion({
  Starting: {},
  Failed: { reason: Schema.String },
  NotFound: {},
  Setup: { setup: Setup.Model },
  Login: { login: Login.Model },
  Consent: { consent: Consent.Model },
  Dashboard: { dashboard: Dashboard.Model },
});

export type Page = typeof Page.Type;

export const Model = Schema.Struct({
  url: Url,
  page: Page,
  tips: Tips.Model,
});

export type Model = typeof Model.Type;

export const routeOf = (model: Model): AppRoute => urlToAppRoute(model.url);
