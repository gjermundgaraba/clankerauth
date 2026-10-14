import { Schema } from "effect";
import { defineTaggedUnion } from "foldkit/schema";
import { Url } from "foldkit/url";
import { Tips } from "@gjermundgaraba-designs/pixel-paper";

import * as Dashboard from "./page/dashboard/index.ts";
import * as Consent from "./page/consent.ts";
import * as Login from "./page/login.ts";
import * as Setup from "./page/setup.ts";
import { type AppRoute, urlToAppRoute } from "./route.ts";

/** Whether the issuer still needs its owner, and otherwise whether this browser is signed in. */
export const Access = defineTaggedUnion({
  SetupRequired: {},
  SignedIn: {},
  SignedOut: {},
});

export type Access = typeof Access.Type;

/** What the document shows. `Starting` waits on whether the issuer has an owner and whether
 *  this browser is signed in, which decide every other page. */
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

/** The route the address names. */
export const routeOf = (model: Model): AppRoute => urlToAppRoute(model.url);
