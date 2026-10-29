import type { Clipboard } from "@effect/platform-browser";
import { SkipLink, Tips } from "@gjermundgaraba/pixel-paper";
import { Effect, Option, Schema, String } from "effect";
import { Command, Subscription } from "foldkit";
import type { Runtime } from "foldkit";
import { UrlRequest, load, pushUrl, replaceUrl } from "foldkit/navigation";
import { modifyFields } from "foldkit/struct";
import * as Update from "foldkit/update";
import { toString as urlToString } from "foldkit/url";
import type { Url } from "foldkit/url";

import { isSignedIn, issuer, toOwnerSentence } from "./api.ts";
import { Message } from "./message.ts";
import { Access, Page, routeOf } from "./model.ts";
import type { Model } from "./model.ts";
import * as Consent from "./page/consent.ts";
import * as Dashboard from "./page/dashboard/index.ts";
import * as Login from "./page/login.ts";
import * as Setup from "./page/setup.ts";
import {
  AppRoute,
  clientsRouter,
  isDashboardRoute,
  loginRouter,
  setupRouter,
  urlToAppRoute,
} from "./route.ts";

type UpdateReturn = Update.Return<Model, Message, Clipboard.Clipboard>;

export const CheckAccess = Command.define("CheckAccess", {
  messages: [Message.SucceededCheckAccess, Message.FailedCheckAccess],
  execute: issuer.setupStatus().pipe(
    toOwnerSentence,
    Effect.flatMap(({ required }): Effect.Effect<Access, string> =>
      required
        ? Effect.succeed(Access.SetupRequired())
        : Effect.map(isSignedIn, (hasSession) =>
            hasSession ? Access.SignedIn() : Access.SignedOut()
          )
    ),
    Effect.match({
      onFailure: (reason) => Message.FailedCheckAccess({ reason }),
      onSuccess: (access) => Message.SucceededCheckAccess({ access }),
    })
  ),
});

export const NavigateInternal = Command.define("NavigateInternal", {
  args: { url: Schema.String },
  messages: [Message.CompletedNavigateInternal],
  execute: ({ url }) =>
    pushUrl(url).pipe(Effect.as(Message.CompletedNavigateInternal())),
});

export const ReplaceUrl = Command.define("ReplaceUrl", {
  args: { url: Schema.String },
  messages: [Message.CompletedReplaceUrl],
  execute: ({ url }) =>
    replaceUrl(url).pipe(Effect.as(Message.CompletedReplaceUrl())),
});

export const LoadUrl = Command.define("LoadUrl", {
  args: { href: Schema.String },
  messages: [Message.CompletedLoadUrl],
  execute: ({ href }) => load(href).pipe(Effect.as(Message.CompletedLoadUrl())),
});

export const ReloadPage = Command.define("ReloadPage", {
  messages: [Message.CompletedReloadPage],
  execute: Effect.sync(() => {
    location.reload();
  }).pipe(Effect.as(Message.CompletedReloadPage())),
});

const searchOf = (url: Url): string => Option.getOrElse(url.search, () => "");

const toSetupMessage = (message: Setup.Message): Message =>
  Message.GotSetupMessage({ message });

const toLoginMessage = (message: Login.Message): Message =>
  Message.GotLoginMessage({ message });

const toConsentMessage = (message: Consent.Message): Message =>
  Message.GotConsentMessage({ message });

const toDashboardMessage = (message: Dashboard.Message): Message =>
  Message.GotDashboardMessage({ message });

const withPage = (model: Model, page: Page): Model =>
  modifyFields(model, { page: () => page });

const setupPage = (model: Model): UpdateReturn => ({
  model: withPage(model, Page.Setup({ setup: Setup.init() })),
});

const loginPage = (
  model: Model,
  search: string,
  destination: string
): UpdateReturn => ({
  model: withPage(
    model,
    Page.Login({ login: Login.init(search, destination) })
  ),
});

const signedInLoginPage = (model: Model, search: string): UpdateReturn => {
  const login = Login.init(search, clientsRouter());

  return Option.match(Login.continuationOf(login), {
    onNone: () => ({ model: withPage(model, Page.Login({ login })) }),
    onSome: (continuation) => ({
      model,
      commands: Command.mapMessages([continuation], toLoginMessage),
    }),
  });
};

const consentPage = (model: Model, search: string): UpdateReturn =>
  Update.foldChildInit(Consent.init(search), {
    toParentModel: (consent) => withPage(model, Page.Consent({ consent })),
    toParentMessage: toConsentMessage,
  });

const dashboardPage = (model: Model): UpdateReturn =>
  Update.foldChildInit(Dashboard.init(), {
    toParentModel: (dashboard) =>
      withPage(model, Page.Dashboard({ dashboard })),
    toParentMessage: toDashboardMessage,
  });

const notFoundPage = (model: Model): UpdateReturn => ({
  model: withPage(model, Page.NotFound()),
});

const redirected = (page: UpdateReturn, url: string): UpdateReturn => ({
  model: page.model,
  commands: [...(page.commands ?? []), ReplaceUrl({ url })],
});

const pageFor = (model: Model, access: Access): UpdateReturn => {
  const route = routeOf(model);

  const search = searchOf(model.url);

  return Access.match<UpdateReturn>(access, {
    SetupRequired: () =>
      AppRoute.guards.Setup(route)
        ? setupPage(model)
        : redirected(setupPage(model), setupRouter()),
    SignedIn: () =>
      AppRoute.match<UpdateReturn>(route, {
        Clients: () => dashboardPage(model),
        Resources: () => dashboardPage(model),
        Keys: () => dashboardPage(model),
        Login: () => signedInLoginPage(model, search),
        Setup: () => redirected(dashboardPage(model), clientsRouter()),
        Consent: () => consentPage(model, search),
        NotFound: () => notFoundPage(model),
      }),
    SignedOut: () =>
      AppRoute.match<UpdateReturn>(route, {
        Clients: () => loginPage(model, search, model.url.pathname),
        Resources: () => loginPage(model, search, model.url.pathname),
        Keys: () => loginPage(model, search, model.url.pathname),
        Login: () => loginPage(model, search, clientsRouter()),
        Setup: () =>
          redirected(loginPage(model, "", clientsRouter()), loginRouter()),
        Consent: () => consentPage(model, search),
        NotFound: () => notFoundPage(model),
      }),
  });
};

const isServedBy = (page: Page, route: AppRoute): boolean =>
  Page.match(page, {
    Starting: () => true,
    Failed: () => false,
    NotFound: () => AppRoute.guards.NotFound(route),
    Setup: () => AppRoute.guards.Setup(route),
    Login: () => AppRoute.guards.Login(route),
    Consent: () => AppRoute.guards.Consent(route),
    Dashboard: () => isDashboardRoute(route),
  });

export const init: Runtime.RoutingApplicationInit<
  Model,
  Message,
  void,
  Clipboard.Clipboard
> = (url) => ({
  model: {
    url,
    page: Page.Starting(),
    tips: Tips.init({ id: "page-tip" }),
  },
  commands: [CheckAccess()],
});

const foldSetupOutMessage = Setup.OutMessage.match<
  Update.Step<Model, Message, Clipboard.Clipboard>
>({
  CreatedOwner: () => (stepModel) =>
    redirected(dashboardPage(stepModel), clientsRouter()),
  FoundOwner: () => (stepModel) =>
    redirected(loginPage(stepModel, "", clientsRouter()), loginRouter()),
});

const foldSetup = Update.foldChild({
  update: Setup.update,
  read: (model: Model) =>
    Page.matchOrElse(
      model.page,
      { Setup: ({ setup }) => Option.some(setup) },
      () => Option.none<Setup.Model>()
    ),
  write: (model, nextSetup) =>
    withPage(model, Page.Setup({ setup: nextSetup })),
  toParentMessage: toSetupMessage,
  foldOutMessage: foldSetupOutMessage,
});

const foldLogin = Update.foldChild({
  update: Login.update,
  read: (model: Model) =>
    Page.matchOrElse(
      model.page,
      { Login: ({ login }) => Option.some(login) },
      () => Option.none<Login.Model>()
    ),
  write: (model, nextLogin) =>
    withPage(model, Page.Login({ login: nextLogin })),
  toParentMessage: toLoginMessage,
});

const foldConsent = Update.foldChild({
  update: Consent.update,
  read: (model: Model) =>
    Page.matchOrElse(
      model.page,
      { Consent: ({ consent }) => Option.some(consent) },
      () => Option.none<Consent.Model>()
    ),
  write: (model, nextConsent) =>
    withPage(model, Page.Consent({ consent: nextConsent })),
  toParentMessage: toConsentMessage,
});

const foldDashboard = Update.foldChild({
  update: Dashboard.update,
  read: (model: Model) =>
    Page.matchOrElse(
      model.page,
      { Dashboard: ({ dashboard }) => Option.some(dashboard) },
      () => Option.none<Dashboard.Model>()
    ),
  write: (model, nextDashboard) =>
    withPage(model, Page.Dashboard({ dashboard: nextDashboard })),
  toParentMessage: toDashboardMessage,
});

const foldTips = Update.foldChild({
  update: Tips.update,
  read: (model: Model) => Option.some(model.tips),
  write: (model, nextTips) => modifyFields(model, { tips: () => nextTips }),
  toParentMessage: (message) => Message.GotTipsMessage({ message }),
});

const isSameSearch = Option.makeEquivalence(String.Equivalence);

const fragmentOf = (model: Model, url: Url): Option.Option<string> =>
  url.pathname === model.url.pathname &&
  isSameSearch(url.search, model.url.search)
    ? url.hash
    : Option.none();

const internalLinkClicked = (model: Model, url: Url): UpdateReturn =>
  Option.match(fragmentOf(model, url), {
    onSome: (fragment) => ({
      model,
      commands: [
        SkipLink.ScrollToFragment({ maybeFragment: Option.some(fragment) }),
      ],
    }),
    onNone: () =>
      isServedBy(model.page, urlToAppRoute(url))
        ? { model, commands: [NavigateInternal({ url: urlToString(url) })] }
        : { model, commands: [LoadUrl({ href: urlToString(url) })] },
  });

const linkClicked = (model: Model, request: UrlRequest): UpdateReturn =>
  UrlRequest.match<UpdateReturn>(request, {
    Internal: ({ url }) => internalLinkClicked(model, url),
    External: ({ href }) => ({ model, commands: [LoadUrl({ href })] }),
  });

const urlChanged = (model: Model, url: Url): UpdateReturn =>
  isServedBy(model.page, urlToAppRoute(url))
    ? {
        model: modifyFields(model, { url: () => url }),
        commands: [SkipLink.ScrollToFragment({ maybeFragment: url.hash })],
      }
    : { model, commands: [ReloadPage()] };

export const update = (model: Model, message: Message) =>
  Message.match<UpdateReturn>(message, {
    SucceededCheckAccess: ({ access }) => pageFor(model, access),
    FailedCheckAccess: ({ reason }) => ({
      model: withPage(model, Page.Failed({ reason })),
    }),
    ClickedRetryAccess: () => ({
      model: withPage(model, Page.Starting()),
      commands: [CheckAccess()],
    }),
    ClickedLink: ({ request }) => linkClicked(model, request),
    ChangedUrl: ({ url }) => urlChanged(model, url),
    CompletedNavigateInternal: () => ({ model }),
    CompletedReplaceUrl: () => ({ model }),
    CompletedLoadUrl: () => ({ model }),
    CompletedReloadPage: () => ({ model }),
    CompletedScrollToFragment: () => ({ model }),
    GotSetupMessage: ({ message: setupMessage }) =>
      foldSetup(model, setupMessage),
    GotLoginMessage: ({ message: loginMessage }) =>
      foldLogin(model, loginMessage),
    GotConsentMessage: ({ message: consentMessage }) =>
      foldConsent(model, consentMessage),
    GotDashboardMessage: ({ message: dashboardMessage }) =>
      foldDashboard(model, dashboardMessage),
    GotTipsMessage: ({ message: tipsMessage }) => foldTips(model, tipsMessage),
  });

export const subscriptions = Subscription.lift(Tips.subscriptions("tip"))<
  Model,
  Message
>({
  read: (model) => Option.some(model.tips),
  toParentMessage: (message) => Message.GotTipsMessage({ message }),
});
