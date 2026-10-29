import {
  Announcer,
  Button,
  Deck,
  LinkButton,
  Loading,
  Outcome,
  SkipLink,
  Tips,
} from "@gjermundgaraba/pixel-paper";
import type { Document, Html, HtmlBuilder } from "foldkit/html";

import { Message } from "./message.ts";
import { Page, routeOf } from "./model.ts";
import type { Model } from "./model.ts";
import * as Consent from "./page/consent.ts";
import * as Dashboard from "./page/dashboard/index.ts";
import * as Login from "./page/login.ts";
import * as Setup from "./page/setup.ts";
import { PRODUCT, wallCardView } from "./page/wall.ts";
import {
  AppRoute,
  clientsRouter,
  isDashboardRoute,
  loginRouter,
} from "./route.ts";
import type { DashboardRoute } from "./route.ts";

const titled = (title: string): string => `${title} | ${PRODUCT}`;

const sectionOf = (route: AppRoute): DashboardRoute =>
  isDashboardRoute(route) ? route : AppRoute.Clients();

const dashboardTitle = (route: AppRoute): string =>
  AppRoute.matchOrElse(
    sectionOf(route),
    { Resources: () => titled("Resources"), Keys: () => titled("API keys") },
    () => titled("Clients")
  );

const titleOf = (model: Model): string =>
  Page.match(model.page, {
    Starting: () => PRODUCT,
    Failed: () => titled("Unable to continue"),
    NotFound: () => titled("Not found"),
    Setup: () => titled("Set up"),
    Login: () => titled("Sign in"),
    Consent: () => titled("Allow access"),
    Dashboard: () => dashboardTitle(routeOf(model)),
  });

const startingView = (h: HtmlBuilder<Message>): Html =>
  Deck.view(
    {
      body: [
        h.h1([h.Class("sr-only")], [PRODUCT]),
        Loading.view({ isLoading: true, label: "loading" }, h),
      ],
    },
    h
  );

const failedView = (reason: string, h: HtmlBuilder<Message>): Html =>
  wallCardView(
    "Unable to continue",
    {
      title: PRODUCT,
      meta: "not available",
      actions: [
        LinkButton.view({ label: "sign in", href: loginRouter() }, h),
        Button.view(
          {
            label: "try again",
            variant: "Primary",
            isDefault: true,
            onClick: Message.ClickedRetryAccess(),
          },
          h
        ),
      ],
      body: [
        Outcome.view(
          { tone: "Error", title: "Unable to continue", body: [reason] },
          h
        ),
      ],
    },
    h
  );

const notFoundView = (h: HtmlBuilder<Message>): Html =>
  wallCardView(
    "Not found",
    {
      title: PRODUCT,
      meta: "404",
      actions: [
        LinkButton.view(
          { label: "go to the dashboard", href: clientsRouter() },
          h
        ),
      ],
      body: [
        Outcome.view(
          {
            tone: "Error",
            title: "Not found",
            body: ["Nothing lives at this address."],
          },
          h
        ),
      ],
    },
    h
  );

const pageView = (model: Model, h: HtmlBuilder<Message>): Html =>
  Page.match(model.page, {
    Starting: () => startingView(h),
    Failed: ({ reason }) => failedView(reason, h),
    NotFound: () => notFoundView(h),
    Setup: ({ setup }) =>
      h.submodel({
        slotId: "setup",
        model: setup,
        view: Setup.view,
        toParentMessage: (message) => Message.GotSetupMessage({ message }),
      }),
    Login: ({ login }) =>
      h.submodel({
        slotId: "login",
        model: login,
        view: Login.view,
        toParentMessage: (message) => Message.GotLoginMessage({ message }),
      }),
    Consent: ({ consent }) =>
      h.submodel({
        slotId: "consent",
        model: consent,
        view: Consent.view,
        toParentMessage: (message) => Message.GotConsentMessage({ message }),
      }),
    Dashboard: ({ dashboard }) =>
      h.submodel({
        slotId: "dashboard",
        model: dashboard,
        view: Dashboard.view,
        viewInputs: { section: sectionOf(routeOf(model)) },
        toParentMessage: (message) => Message.GotDashboardMessage({ message }),
      }),
  });

const isLiveRegionInDialog = (page: Page): boolean =>
  Page.matchOrElse(
    page,
    { Dashboard: ({ dashboard }) => Dashboard.isDialogOpen(dashboard) },
    () => false
  );

export const view = (model: Model, h: HtmlBuilder<Message>): Document => ({
  title: titleOf(model),
  body: h.div(
    [],
    [
      SkipLink.view(h),
      pageView(model, h),
      ...(isLiveRegionInDialog(model.page) ? [] : [Announcer.view(h)]),
      h.submodel({
        slotId: Tips.id(model.tips),
        model: model.tips,
        view: Tips.view,
        toParentMessage: (message) => Message.GotTipsMessage({ message }),
      }),
    ]
  ),
});
