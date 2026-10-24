import { Option } from "effect";
import {
  Command,
  Mount,
  click,
  expect,
  given,
  inside,
  label,
  role,
  scene,
  text,
  type,
  withViewInputs,
} from "foldkit/scene";
import { modifyFields } from "foldkit/struct";
import { Dialog as UiDialog } from "@foldkit/ui";
import { Announcer, Card, Dialog, Focus, TopBar } from "@gjermundgaraba-designs/pixel-paper";
import { describe, test } from "vite-plus/test";

import { AppRoute } from "../../route.ts";
import { Change } from "./change.ts";
import { SaveChange, SignOut } from "./command.ts";
import { EDITOR_FORM_ID } from "./constant.ts";
import { Message, update, view } from "./index.ts";
import {
  SECOND_READ,
  THIRD_READ,
  cataloged,
  listed,
  listing,
  readOf,
  staleListed,
  unlisted,
} from "./dashboard.fixture.ts";
import { listingQuery } from "./listing.ts";
import { Activity } from "./model.ts";

const clientsView = withViewInputs(view, { section: AppRoute.Clients() })();

const keysView = withViewInputs(view, { section: AppRoute.Keys() })();

const resourcesView = withViewInputs(view, { section: AppRoute.Resources() })();

const deleteKey = Change.DeleteKey({ keyId: "fixture-key", name: "Automation" });

const showDialog = [
  Command.resolve(UiDialog.ShowDialog, UiDialog.Message.SucceededShowDialog()),
  Mount.resolveAll(...Dialog.sceneMounts),
];

const closeDialog = Command.resolve(UiDialog.CloseDialog, UiDialog.Message.CompletedCloseDialog());

const measureTopBar = Mount.resolveAll(
  ...TopBar.sceneMounts((message) => Message.GotTopBarMessage({ message })),
);

describe("dashboard view", () => {
  test("deleting a key asks first, and a refusal is shown in the question", () => {
    scene(
      { update, view: keysView },
      given(listed),
      measureTopBar,
      click(role("button", { name: "delete Automation" })),
      ...showDialog,
      inside(
        role("alertdialog", { name: "Delete API key" }),
        expect(text("Delete this API key?")).toExist(),
        click(role("button", { name: "delete" })),
      ),
      Command.resolve(
        SaveChange({ change: deleteKey }),
        Message.FailedSaveChange({ reason: "Fixture request failed" }),
      ),
      inside(
        role("alertdialog", { name: "Delete API key" }),
        expect(text("Not saved")).toExist(),
        expect(text("Fixture request failed")).toExist(),
      ),
    );
  });

  test("a deleted key leaves the question closed and the page announced", () => {
    scene(
      { update, view: keysView },
      given(listed),
      measureTopBar,
      click(role("button", { name: "delete Automation" })),
      ...showDialog,
      inside(
        role("alertdialog", { name: "Delete API key" }),
        click(role("button", { name: "delete" })),
      ),
      Command.resolve(
        SaveChange,
        Message.SucceededSaveChange({ change: deleteKey, maybeCredential: Option.none() }),
      ),
      closeDialog,
      Command.resolveAll(
        [listingQuery.Fetch, readOf(SECOND_READ, listing)],
        [Announcer.Announce, Message.CompletedAnnounce()],
      ),
      Mount.expectEnded(UiDialog.AcquireResources, Dialog.BindActionKeys),
      expect(role("alertdialog", { name: "Delete API key" })).toBeAbsent(),
    );
  });

  test("a resource the issuer refuses stays in the editor as typed, with the reason", () => {
    scene(
      { update, view: resourcesView },
      given(listed),
      measureTopBar,
      click(role("button", { name: "add resource" })),
      ...showDialog,
      inside(
        role("dialog", { name: "Add resource" }),
        type(label("Name"), "Second API"),
        type(label("HTTP or HTTPS identifier"), "https://second.fixture.invalid"),
        type(label("Scopes"), "read write"),
        click(role("button", { name: "add resource" })),
      ),
      Command.resolve(Focus.Focus({ id: Card.submitId(EDITOR_FORM_ID) }), Message.CompletedFocus()),
      Command.resolve(
        SaveChange({
          change: Change.PutResource({
            identifier: "https://second.fixture.invalid",
            name: "Second API",
            scopes: ["read", "write"],
          }),
        }),
        Message.FailedSaveChange({ reason: "Fixture request failed" }),
      ),
      inside(
        role("dialog", { name: "Add resource" }),
        expect(text("Fixture request failed")).toExist(),
        expect(label("Name")).toHaveValue("Second API"),
        expect(label("HTTP or HTTPS identifier")).toHaveValue("https://second.fixture.invalid"),
      ),
    );
  });

  test("a managed client offers every change, an automatic one only its authorization", () => {
    scene(
      { update, view: clientsView },
      given(cataloged),
      measureTopBar,
      expect(role("button", { name: "edit Managed client" })).toExist(),
      expect(role("button", { name: "access Managed client" })).toExist(),
      expect(role("button", { name: "rotate secret Managed client" })).toExist(),
      expect(role("button", { name: "delete Managed client" })).toExist(),
      expect(role("button", { name: "revoke all Automatic client" })).toExist(),
      expect(role("button", { name: "block Automatic client" })).toExist(),
      expect(role("button", { name: "forget Automatic client" })).toExist(),
      expect(role("button", { name: "edit Automatic client" })).toBeAbsent(),
      expect(role("button", { name: "access Automatic client" })).toBeAbsent(),
      expect(role("button", { name: "rotate secret Automatic client" })).toBeAbsent(),
      expect(role("button", { name: "delete Automatic client" })).toBeAbsent(),
    );
  });

  test("the built-in administration resource is fixed, and API keys are granted on it", () => {
    scene(
      { update, view: resourcesView },
      given(cataloged),
      measureTopBar,
      expect(role("button", { name: "edit Fixture API" })).toExist(),
      expect(role("button", { name: "edit clankerauth administration" })).toBeAbsent(),
      expect(role("button", { name: "delete clankerauth administration" })).toBeAbsent(),
    );

    scene(
      { update, view: keysView },
      given(cataloged),
      measureTopBar,
      click(role("button", { name: "create key" })),
      ...showDialog,
      inside(
        role("dialog", { name: "Create API key" }),
        expect(text("Fixture API", { exact: false })).toExist(),
        expect(text("clankerauth administration", { exact: false })).toExist(),
      ),
    );
  });

  test("nothing else is offered while a change saves", () => {
    scene(
      { update, view: keysView },
      given(modifyFields(listed, { activity: () => Activity.Saving() })),
      measureTopBar,
      expect(role("button", { name: "Sign out" })).toBeDisabled(),
      expect(role("button", { name: "create key" })).toBeDisabled(),
      expect(role("button", { name: "delete Automation" })).toBeDisabled(),
    );
  });

  test("a refused sign-out says why on the page", () => {
    scene(
      { update, view: keysView },
      given(listed),
      measureTopBar,
      click(role("button", { name: "Sign out" })),
      Command.resolve(SignOut(), Message.FailedSignOut({ reason: "Fixture request failed" })),
      Command.resolve(Focus.Focus, Message.CompletedFocus()),
      expect(text("Not signed out")).toExist(),
    );
  });

  test("a listing that could not refresh can be read again", () => {
    scene(
      { update, view: keysView },
      given(staleListed),
      measureTopBar,
      expect(text("Not refreshed")).toExist(),
      click(role("button", { name: "retry refresh" })),
      Command.resolve(listingQuery.Fetch, readOf(THIRD_READ, listing)),
      expect(text("Not refreshed")).toBeAbsent(),
    );
  });

  test("a listing that could not be read says why and can be read again", () => {
    scene(
      { update, view: keysView },
      given(unlisted),
      expect(text("Fixture request failed")).toExist(),
      click(role("button", { name: "try again" })),
      Command.resolve(listingQuery.Fetch, readOf(SECOND_READ, listing)),
      measureTopBar,
      expect(role("heading", { name: "API keys" })).toExist(),
    );
  });
});
