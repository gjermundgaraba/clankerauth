import { Schema, pipe } from "effect";
import { Route } from "foldkit";
import { defineRouteUnion, literal } from "foldkit/route";

export const AppRoute = defineRouteUnion({
  Clients: {},
  Resources: {},
  Keys: {},
  Login: {},
  Setup: {},
  Consent: {},
  NotFound: { path: Schema.String },
});

export type AppRoute = typeof AppRoute.Type;

const dashboardScreens = ["Clients", "Resources", "Keys"] as const;

export const DashboardRoute = AppRoute.subset(dashboardScreens);

export type DashboardRoute = typeof DashboardRoute.Type;

export const clientsRouter = pipe(Route.root, Route.mapTo(AppRoute.Clients));

export const resourcesRouter = pipe(literal("resources"), Route.mapTo(AppRoute.Resources));

export const keysRouter = pipe(literal("keys"), Route.mapTo(AppRoute.Keys));

export const loginRouter = pipe(literal("login"), Route.mapTo(AppRoute.Login));

export const setupRouter = pipe(literal("setup"), Route.mapTo(AppRoute.Setup));

const consentRouter = pipe(literal("consent"), Route.mapTo(AppRoute.Consent));

const routeParser = Route.oneOf(
  resourcesRouter,
  keysRouter,
  loginRouter,
  setupRouter,
  consentRouter,
  clientsRouter,
);

export const urlToAppRoute = Route.parseUrlWithFallback(routeParser, AppRoute.NotFound);

export const isDashboardRoute = AppRoute.isAnyOf(dashboardScreens);
