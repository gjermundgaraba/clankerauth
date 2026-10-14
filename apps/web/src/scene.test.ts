import {
  Command,
  Mount,
  all,
  click,
  expect,
  expectAll,
  given,
  inside,
  label,
  role,
  scene,
  submit,
  text,
  type,
} from "foldkit/scene";
import type { Url } from "foldkit/url";
import { modifyFields } from "foldkit/struct";
import { Dialog as UiDialog } from "@foldkit/ui";
import { Dialog, Focus, TopBar } from "@gjermundgaraba-designs/pixel-paper";
import { describe, test } from "vite-plus/test";

import { listed } from "./dashboard/dashboard.fixture.ts";
import * as Dashboard from "./dashboard/index.ts";
import { urlAt } from "./fixture.ts";
import { CheckAccess, init, update } from "./main.ts";
import { Message } from "./message.ts";
import { Access, type Model, Page } from "./model.ts";
import * as Login from "./page/login.ts";
import * as Setup from "./page/setup.ts";
import { view } from "./view.ts";

const checkedAt = (url: Url, access: Access): Model =>
  update(init(url).model, Message.SucceededCheckAccess({ access })).model;

describe("application view", () => {
  test("a signed-out owner signs in and goes on to the page that asked for it", () => {
    scene(
      { update, view },
      given(checkedAt(urlAt("/login", "rd=%2Fkeys"), Access.SignedOut())),
      expect(role("heading", { name: "Sign in to clankerauth" })).toExist(),
      type(label("Email"), "owner@fixture.invalid"),
      type(label("Password"), "correct horse"),
      click(role("button", { name: "sign in" })),
      Command.resolve(
        Login.SignIn({ email: "owner@fixture.invalid", password: "correct horse" }),
        Login.Message.SucceededSignIn(),
      ),
      Command.resolve(
        Login.ContinueAfterSignIn({ destination: "/keys" }),
        Login.Message.CompletedContinueAfterSignIn(),
      ),
    );
  });

  test("a refused sign-in says why beside the form", () => {
    scene(
      { update, view },
      given(checkedAt(urlAt("/login"), Access.SignedOut())),
      type(label("Email"), "owner@fixture.invalid"),
      type(label("Password"), "wrong"),
      submit(role("form")),
      Command.resolve(Login.SignIn, Login.Message.FailedSignIn({ reason: "Sign-in failed." })),
      expect(text("Sign-in failed.", { exact: false })).toExist(),
      expect(role("button", { name: "sign in" })).toExist(),
    );
  });

  test("setup names a confirmation that does not match, and moves focus to it", () => {
    scene(
      { update, view },
      given(checkedAt(urlAt("/setup"), Access.SetupRequired())),
      expect(role("heading", { name: "Set up clankerauth" })).toExist(),
      type(label("Email"), "owner@fixture.invalid"),
      type(label("Password"), "correct horse battery"),
      type(label("Confirm password"), "something else"),
      click(role("button", { name: "create account" })),
      Command.resolve(Focus.Focus({ id: "setup-confirmation" }), Setup.Message.CompletedFocus()),
      expect(label("Confirm password")).toHaveAttr("aria-invalid", "true"),
    );
  });

  test("a failed access check says why and asks again on request", () => {
    scene(
      { update, view },
      given(
        update(
          init(urlAt("/")).model,
          Message.FailedCheckAccess({ reason: "Fixture request failed" }),
        ).model,
      ),
      expect(text("Unable to continue")).toExist(),
      expect(text("Fixture request failed", { exact: false })).toExist(),
      click(role("button", { name: "try again" })),
      Command.resolve(CheckAccess(), Message.SucceededCheckAccess({ access: Access.SignedOut() })),
      expect(role("heading", { name: "Sign in to clankerauth" })).toExist(),
    );
  });

  test("the page has one live region, which an open dashboard dialog hosts", () => {
    scene(
      { update, view },
      given(
        modifyFields(init(urlAt("/keys")).model, {
          page: () => Page.Dashboard({ dashboard: listed }),
        }),
      ),
      Mount.resolve(
        { name: TopBar.MeasureHeight.name },
        Dashboard.Message.GotTopBarMessage({ message: TopBar.Message.CompletedMeasureHeight() }),
      ),
      expectAll(all.role("status")).toHaveCount(1),
      click(role("button", { name: "delete Automation" })),
      Command.resolve(UiDialog.ShowDialog, UiDialog.Message.SucceededShowDialog()),
      Mount.resolveAll(
        [UiDialog.AcquireResources, UiDialog.Message.SucceededAcquireResources()],
        [Dialog.BindActionKeys, Dialog.Message.PressedActionKey({ direction: "Next" })],
      ),
      expectAll(all.role("status")).toHaveCount(1),
      inside(role("alertdialog", { name: "Delete API key" }), expect(role("status")).toExist()),
    );
  });
});
