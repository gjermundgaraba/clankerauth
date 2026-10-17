import { Option } from "effect";
import { UrlRequest } from "foldkit/navigation";
import { Command, given, message, model, story } from "foldkit/story";
import type { Url } from "foldkit/url";
import { SkipLink } from "@gjermundgaraba-designs/pixel-paper";
import { describe, expect, test } from "vite-plus/test";

import { FIRST_READ, failedReadOf } from "./page/dashboard/dashboard.fixture.ts";
import { listingQuery } from "./page/dashboard/listing.ts";
import { urlAt } from "./fixture.ts";
import {
  CheckAccess,
  LoadUrl,
  NavigateInternal,
  ReloadPage,
  ReplaceUrl,
  init,
  update,
} from "./main.ts";
import { Message } from "./message.ts";
import { Access, Page } from "./model.ts";
import * as Login from "./page/login.ts";
import * as Setup from "./page/setup.ts";

const startedAt = (url: Url) => given(init(url).model);

const listingFailed = failedReadOf(FIRST_READ);

const loginContinuationOf = (page: Page) =>
  Page.matchOrElse(page, { Login: ({ login }) => Option.some(login.continuation) }, () =>
    Option.none(),
  );

describe("application update", () => {
  test("the application starts by asking whether it has an owner and a session", () => {
    const init_ = init(urlAt("/"));

    expect(init_.commands).toEqual([CheckAccess()]);
    expect(Page.guards.Starting(init_.model.page)).toBe(true);
  });

  test("until the owner exists every address is setup's", () => {
    story(
      update,
      startedAt(urlAt("/keys")),
      message(Message.SucceededCheckAccess({ access: Access.SetupRequired() })),
      model((next) => {
        expect(Page.guards.Setup(next.page)).toBe(true);
      }),
      Command.resolve(ReplaceUrl({ url: "/setup" }), Message.CompletedReplaceUrl()),
    );
  });

  test("a signed-out browser signs in where it stands, and goes on to that page", () => {
    story(
      update,
      startedAt(urlAt("/keys")),
      message(Message.SucceededCheckAccess({ access: Access.SignedOut() })),
      Command.expectNone(),
      model((next) => {
        expect(loginContinuationOf(next.page)).toEqual(
          Option.some(Login.Continuation.RedirectTo({ destination: "/keys" })),
        );
      }),
    );
  });

  test("a sign-in's own destination wins over the page it stands on", () => {
    story(
      update,
      startedAt(urlAt("/login", "rd=%2Fresources")),
      message(Message.SucceededCheckAccess({ access: Access.SignedOut() })),
      model((next) => {
        expect(loginContinuationOf(next.page)).toEqual(
          Option.some(Login.Continuation.RedirectTo({ destination: "/resources" })),
        );
      }),
    );
  });

  test("a signed-in owner at the sign-in goes straight on to its destination", () => {
    story(
      update,
      startedAt(urlAt("/login", "rd=%2Fkeys")),
      message(Message.SucceededCheckAccess({ access: Access.SignedIn() })),
      model((next) => {
        expect(Page.guards.Starting(next.page)).toBe(true);
      }),
      Command.resolve(
        Login.ContinueAfterSignIn({ destination: "/keys" }),
        Login.Message.CompletedContinueAfterSignIn(),
      ),
    );
  });

  test("a signed-in owner inside an authorization still signs in through the form", () => {
    story(
      update,
      startedAt(urlAt("/login", "sig=fixture")),
      message(Message.SucceededCheckAccess({ access: Access.SignedIn() })),
      Command.expectNone(),
      model((next) => {
        expect(Page.guards.Login(next.page)).toBe(true);
      }),
    );
  });

  test("a signed-in owner sees the dashboard, which reads its listing", () => {
    story(
      update,
      startedAt(urlAt("/")),
      message(Message.SucceededCheckAccess({ access: Access.SignedIn() })),
      model((next) => {
        expect(Page.guards.Dashboard(next.page)).toBe(true);
      }),
      Command.resolve(listingQuery.Fetch({ generation: FIRST_READ }), listingFailed),
    );
  });

  test("a failed check shows why, and trying again asks again", () => {
    story(
      update,
      startedAt(urlAt("/")),
      message(Message.FailedCheckAccess({ reason: "Fixture request failed" })),
      model((next) => {
        expect(next.page).toEqual(Page.Failed({ reason: "Fixture request failed" }));
      }),
      message(Message.ClickedRetryAccess()),
      Command.expectExact(CheckAccess()),
      model((next) => {
        expect(Page.guards.Starting(next.page)).toBe(true);
      }),
      Command.resolve(CheckAccess, Message.SucceededCheckAccess({ access: Access.SignedOut() })),
      model((next) => {
        expect(Page.guards.Login(next.page)).toBe(true);
      }),
    );
  });

  test("following a link after a failed check loads the address afresh", () => {
    story(
      update,
      startedAt(urlAt("/")),
      message(Message.FailedCheckAccess({ reason: "Fixture request failed" })),
      message(Message.ClickedLink({ request: UrlRequest.Internal({ url: urlAt("/login") }) })),
      Command.resolve(
        LoadUrl({ href: "https://issuer.fixture.invalid/login" }),
        Message.CompletedLoadUrl(),
      ),
    );
  });

  test("going back to an address the page on show does not answer loads it afresh", () => {
    story(
      update,
      startedAt(urlAt("/")),
      message(Message.SucceededCheckAccess({ access: Access.SignedIn() })),
      Command.resolve(listingQuery.Fetch, listingFailed),
      message(Message.ChangedUrl({ url: urlAt("/consent", "sig=fixture") })),
      Command.resolve(ReloadPage(), Message.CompletedReloadPage()),
      model((next) => {
        expect(Page.guards.Dashboard(next.page)).toBe(true);
      }),
    );
  });

  test("a section's address shows the dashboard in place, with focus at the top", () => {
    story(
      update,
      startedAt(urlAt("/")),
      message(Message.SucceededCheckAccess({ access: Access.SignedIn() })),
      Command.resolve(listingQuery.Fetch({ generation: FIRST_READ }), listingFailed),
      message(Message.ClickedLink({ request: UrlRequest.Internal({ url: urlAt("/keys") }) })),
      Command.resolve(
        NavigateInternal({ url: "https://issuer.fixture.invalid/keys" }),
        Message.CompletedNavigateInternal(),
      ),
      message(Message.ChangedUrl({ url: urlAt("/keys") })),
      model((next) => {
        expect(Page.guards.Dashboard(next.page)).toBe(true);
        expect(next.url.pathname).toBe("/keys");
      }),
      Command.resolve(
        SkipLink.ScrollToFragment({ maybeFragment: Option.none() }),
        Message.CompletedScrollToFragment(),
      ),
    );
  });

  test("the skip link moves focus to the page's main content, and the address stays", () => {
    story(
      update,
      startedAt(urlAt("/login")),
      message(Message.SucceededCheckAccess({ access: Access.SignedOut() })),
      message(
        Message.ClickedLink({
          request: UrlRequest.Internal({ url: urlAt("/login", "", "main") }),
        }),
      ),
      Command.resolve(
        SkipLink.ScrollToFragment({ maybeFragment: Option.some("main") }),
        Message.CompletedScrollToFragment(),
      ),
      model((next) => {
        expect(Page.guards.Login(next.page)).toBe(true);
      }),
    );
  });

  test("the skip link also only moves focus when the page could not continue", () => {
    story(
      update,
      startedAt(urlAt("/")),
      message(Message.FailedCheckAccess({ reason: "Fixture request failed" })),
      message(
        Message.ClickedLink({
          request: UrlRequest.Internal({ url: urlAt("/", "", "main") }),
        }),
      ),
      Command.resolve(
        SkipLink.ScrollToFragment({ maybeFragment: Option.some("main") }),
        Message.CompletedScrollToFragment(),
      ),
      model((next) => {
        expect(Page.guards.Failed(next.page)).toBe(true);
      }),
    );
  });

  test("a new owner lands on the dashboard, at its address", () => {
    story(
      update,
      startedAt(urlAt("/setup")),
      message(Message.SucceededCheckAccess({ access: Access.SetupRequired() })),
      message(
        Message.GotSetupMessage({
          message: Setup.Message.SucceededSetupOwner({ outcome: "Created" }),
        }),
      ),
      model((next) => {
        expect(Page.guards.Dashboard(next.page)).toBe(true);
      }),
      Command.expectExact(listingQuery.Fetch({ generation: FIRST_READ }), ReplaceUrl({ url: "/" })),
      Command.resolveAll(
        [listingQuery.Fetch, listingFailed],
        [ReplaceUrl, Message.CompletedReplaceUrl()],
      ),
    );
  });

  test("a setup someone else finished first sends the owner to sign in", () => {
    story(
      update,
      startedAt(urlAt("/setup")),
      message(Message.SucceededCheckAccess({ access: Access.SetupRequired() })),
      message(
        Message.GotSetupMessage({
          message: Setup.Message.SucceededSetupOwner({ outcome: "AlreadyOwned" }),
        }),
      ),
      model((next) => {
        expect(Page.guards.Login(next.page)).toBe(true);
      }),
      Command.resolve(ReplaceUrl({ url: "/login" }), Message.CompletedReplaceUrl()),
    );
  });
});
