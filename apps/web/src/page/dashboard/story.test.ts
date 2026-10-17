import { AsyncData } from "foldkit";
import { Command, given, message, model, story } from "foldkit/story";
import { modifyFields } from "foldkit/struct";
import { Array, Option } from "effect";
import { Dialog as UiDialog } from "@foldkit/ui";
import {
  Announcer,
  Card,
  ConfirmDialog,
  CopyButton,
  Dialog,
  Focus,
} from "@gjermundgaraba-designs/pixel-paper";
import { describe, expect, test } from "vite-plus/test";

import { Change, Credential } from "./change.ts";
import { SaveChange, SignOut } from "./command.ts";
import { EDITOR_FORM_ID, NOT_REFRESHED, REFUSAL_ID } from "./constant.ts";
import * as Form from "./form.ts";
import {
  SECOND_READ,
  THIRD_READ,
  failedReadOf,
  listed,
  listing,
  readOf,
  rereading,
  staleListed,
} from "./dashboard.fixture.ts";
import { listingQuery } from "./listing.ts";
import { Message } from "./message.ts";
import { Activity, type Model, isHeld, listingOf, refusalAt } from "./model.ts";
import { update } from "./update.ts";

const apiKey = Credential.ApiKey({ keyId: "fixture-key", name: "Automation", key: "once-only" });

const showing = (model: Model, credential: Credential): Model =>
  modifyFields(model, {
    credentials: () => [{ credential, copy: CopyButton.init({ id: "copy-fixture" }) }],
  });

const saving = (model: Model): Model => modifyFields(model, { activity: () => Activity.Saving() });

const disable = Change.SetKeyEnabled({ keyId: "fixture-key", isEnabled: false });

const deleteKey = Change.DeleteKey({ keyId: "fixture-key", name: "Automation" });

const editing = (formMessage: Form.Message) => Message.GotFormMessage({ message: formMessage });

const confirming = (confirmMessage: ConfirmDialog.Message) =>
  Message.GotConfirmMessage({ message: confirmMessage });

const requestingClose = Dialog.Message.GotDialogMessage({
  message: UiDialog.Message.RequestedClose(),
});

const askingToCloseEditor = Message.GotEditorMessage({ message: requestingClose });

const created = Change.PutResource({
  identifier: "https://second.fixture.invalid",
  name: "Fixture API",
  scopes: ["read", "write"],
});

const submittingCreated = [
  message(Message.ClickedOpenForm({ form: Form.addResource() })),
  Command.resolve(UiDialog.ShowDialog, UiDialog.Message.SucceededShowDialog()),
  message(editing(Form.Message.UpdatedResourceName({ value: " Fixture API " }))),
  message(
    editing(Form.Message.UpdatedResourceIdentifier({ value: "https://second.fixture.invalid" })),
  ),
  message(editing(Form.Message.UpdatedResourceScopes({ value: "read  write" }))),
  message(Message.SubmittedForm()),
  Command.expectExact(
    Focus.Focus({ id: Card.submitId(EDITOR_FORM_ID) }),
    SaveChange({ change: created }),
  ),
  Command.resolve(Focus.Focus, Message.CompletedFocus()),
];

describe("dashboard update", () => {
  test("a change asked for while another saves is ignored", () => {
    story(
      update,
      given(saving(listed)),
      message(Message.ClickedChange({ change: disable })),
      Command.expectNone(),
      model((next) => {
        expect(next.activity).toEqual(Activity.Saving());
      }),
    );
  });

  test("a change saves at once when it destroys nothing", () => {
    story(
      update,
      given(listed),
      message(Message.ClickedChange({ change: disable })),
      Command.expectExact(SaveChange({ change: disable })),
      model((next) => {
        expect(isHeld(next)).toBe(true);
      }),
      Command.resolve(
        SaveChange,
        Message.SucceededSaveChange({ change: disable, maybeCredential: Option.none() }),
      ),
      model((next) => {
        expect(next.activity).toEqual(Activity.Idle());
        expect(AsyncData.isRefreshing(listingOf(next))).toBe(true);
        expect(isHeld(next)).toBe(true);
      }),
      Command.resolveAll(
        [listingQuery.Fetch, readOf(SECOND_READ, listing)],
        [Announcer.Announce, Message.CompletedAnnounce()],
      ),
      model((next) => {
        expect(isHeld(next)).toBe(false);
      }),
    );
  });

  test("a refusal outside a dialog lands on the page and takes focus", () => {
    story(
      update,
      given(saving(listed)),
      message(Message.FailedSaveChange({ reason: "Fixture request failed" })),
      Command.resolve(Focus.Focus({ id: REFUSAL_ID }), Message.CompletedFocus()),
      model((next) => {
        expect(next.activity).toEqual(Activity.Idle());
        expect(next.maybeRefusal).toEqual(
          Option.some({ place: "Page", title: "Not saved", reason: "Fixture request failed" }),
        );
      }),
    );
  });

  test("a change that destroys something is asked about, then saved in its dialog, which closes still asking it", () => {
    story(
      update,
      given(listed),
      message(Message.ClickedChange({ change: deleteKey })),
      Command.expectHas(UiDialog.ShowDialog),
      Command.resolve(UiDialog.ShowDialog, UiDialog.Message.SucceededShowDialog()),
      model((next) => {
        expect(ConfirmDialog.isOpen(next.confirm)).toBe(true);
        expect(next.maybePending).toEqual(Option.some(deleteKey));
      }),
      message(confirming(ConfirmDialog.Message.ClickedConfirm())),
      Command.expectExact(SaveChange({ change: deleteKey })),
      model((next) => {
        expect(next.activity).toEqual(Activity.Saving());
      }),
      Command.resolve(
        SaveChange,
        Message.SucceededSaveChange({ change: deleteKey, maybeCredential: Option.none() }),
      ),
      Command.resolveAll(
        [UiDialog.CloseDialog, UiDialog.Message.CompletedCloseDialog()],
        [listingQuery.Fetch, readOf(SECOND_READ, listing)],
        [Announcer.Announce, Message.CompletedAnnounce()],
      ),
      model((next) => {
        expect(ConfirmDialog.isOpen(next.confirm)).toBe(false);
        expect(next.maybePending).toEqual(Option.some(deleteKey));
        expect(isHeld(next)).toBe(false);
      }),
    );
  });

  test("a cancelled question saves nothing", () => {
    story(
      update,
      given(listed),
      message(Message.ClickedChange({ change: deleteKey })),
      Command.resolve(UiDialog.ShowDialog, UiDialog.Message.SucceededShowDialog()),
      message(confirming(ConfirmDialog.Message.ClickedCancel())),
      Command.resolve(UiDialog.CloseDialog, UiDialog.Message.CompletedCloseDialog()),
      Command.expectNone(),
      model((next) => {
        expect(ConfirmDialog.isOpen(next.confirm)).toBe(false);
        expect(next.activity).toEqual(Activity.Idle());
      }),
    );
  });

  test("a refusal inside the question stays in its dialog, without moving focus", () => {
    story(
      update,
      given(listed),
      message(Message.ClickedChange({ change: deleteKey })),
      Command.resolve(UiDialog.ShowDialog, UiDialog.Message.SucceededShowDialog()),
      message(confirming(ConfirmDialog.Message.ClickedConfirm())),
      Command.resolve(SaveChange, Message.FailedSaveChange({ reason: "Fixture request failed" })),
      Command.expectNone(),
      model((next) => {
        expect(ConfirmDialog.isOpen(next.confirm)).toBe(true);
        expect(next.activity).toEqual(Activity.Idle());
        expect(Option.isSome(refusalAt(next, "Confirm"))).toBe(true);
        expect(Option.isNone(refusalAt(next, "Page"))).toBe(true);
      }),
    );
  });

  test("a submitted form saves its change, and the editor closes once saved, still showing it", () => {
    story(
      update,
      given(listed),
      ...submittingCreated,
      model((next) => {
        expect(next.activity).toEqual(Activity.Saving());
      }),
      Command.resolve(
        SaveChange,
        Message.SucceededSaveChange({ change: created, maybeCredential: Option.none() }),
      ),
      Command.resolveAll(
        [UiDialog.CloseDialog, UiDialog.Message.CompletedCloseDialog()],
        [listingQuery.Fetch, readOf(SECOND_READ, listing)],
        [Announcer.Announce, Message.CompletedAnnounce()],
      ),
      model((next) => {
        expect(Dialog.isOpen(next.editor)).toBe(false);
        expect(Option.isSome(next.maybeForm)).toBe(true);
      }),
    );
  });

  test("the editor: a close while busy changes nothing", () => {
    story(
      update,
      given(
        saving(
          modifyFields(listed, {
            editor: (editor) => Dialog.open(editor).model,
            maybeForm: () => Option.some(Form.addResource()),
          }),
        ),
      ),
      message(askingToCloseEditor),
      Command.expectNone(),
      model((next) => {
        expect(Dialog.isOpen(next.editor)).toBe(true);
      }),
    );
  });

  test("the question: a close while busy changes nothing", () => {
    story(
      update,
      given(
        saving(
          modifyFields(listed, {
            confirm: (confirm) => ConfirmDialog.open(confirm).model,
            maybePending: () => Option.some(deleteKey),
          }),
        ),
      ),
      message(confirming(ConfirmDialog.Message.GotDialogMessage({ message: requestingClose }))),
      message(confirming(ConfirmDialog.Message.ClickedCancel())),
      Command.expectNone(),
      model((next) => {
        expect(ConfirmDialog.isOpen(next.confirm)).toBe(true);
      }),
    );
  });

  test("the editor can be left once its save is refused", () => {
    story(
      update,
      given(listed),
      ...submittingCreated,
      Command.resolve(SaveChange, Message.FailedSaveChange({ reason: "Fixture request failed" })),
      Command.expectNone(),
      model((next) => {
        expect(next.activity).toEqual(Activity.Idle());
        expect(Dialog.isOpen(next.editor)).toBe(true);
        expect(Option.map(refusalAt(next, "Editor"), ({ reason }) => reason)).toEqual(
          Option.some("Fixture request failed"),
        );
      }),
      message(askingToCloseEditor),
      Command.resolve(UiDialog.CloseDialog, UiDialog.Message.CompletedCloseDialog()),
      model((next) => {
        expect(Dialog.isOpen(next.editor)).toBe(false);
      }),
    );
  });

  test("adding a resource the listing already holds is refused in the editor", () => {
    story(
      update,
      given(listed),
      message(Message.ClickedOpenForm({ form: Form.addResource() })),
      Command.resolve(UiDialog.ShowDialog, UiDialog.Message.SucceededShowDialog()),
      message(editing(Form.Message.UpdatedResourceName({ value: "Again" }))),
      message(
        editing(Form.Message.UpdatedResourceIdentifier({ value: " https://api.fixture.invalid " })),
      ),
      message(Message.SubmittedForm()),
      Command.expectNone(),
      model((next) => {
        expect(Option.map(refusalAt(next, "Editor"), ({ reason }) => reason)).toEqual(
          Option.some("A Resource with this identifier exists already: edit it instead."),
        );
      }),
    );
  });

  test("a form that does not read as a change is refused in the editor", () => {
    story(
      update,
      given(listed),
      message(Message.ClickedOpenForm({ form: Form.registerClient() })),
      Command.resolve(UiDialog.ShowDialog, UiDialog.Message.SucceededShowDialog()),
      message(editing(Form.Message.UpdatedClientName({ value: "Fixture client" }))),
      message(Message.SubmittedForm()),
      Command.expectNone(),
      model((next) => {
        expect(next.activity).toEqual(Activity.Idle());
        expect(Option.map(refusalAt(next, "Editor"), ({ reason }) => reason)).toEqual(
          Option.some("Add at least one redirect URI."),
        );
      }),
    );
  });

  test("a rotated secret replaces the one shown before and takes focus, without a reread", () => {
    const rotate = Change.RotateSecret({ clientId: "fixture-client" });

    const secret = Credential.ClientSecret({
      clientId: "fixture-client",
      name: "Fixture client",
      secret: "once-only",
    });

    const previous = Credential.ClientSecret({
      clientId: "fixture-client",
      name: "Fixture client",
      secret: "shown before",
    });

    story(
      update,
      given(showing(saving(listed), previous)),
      message(
        Message.SucceededSaveChange({ change: rotate, maybeCredential: Option.some(secret) }),
      ),
      Command.expectExact(
        Announcer.Announce({ text: "Secret rotated. Store it now." }),
        Focus.Focus({ id: "copy-client:fixture-client" }),
      ),
      Command.resolveAll(
        [Announcer.Announce, Message.CompletedAnnounce()],
        [Focus.Focus, Message.CompletedFocus()],
      ),
      model((next) => {
        expect(Array.map(next.credentials, ({ credential }) => credential)).toEqual([secret]);
      }),
    );
  });

  test("credentials outlive a reread that fails", () => {
    story(
      update,
      given(showing(rereading(listed), apiKey)),
      message(Message.GotListingMessage({ message: failedReadOf(SECOND_READ) })),
      model((next) => {
        expect(AsyncData.isStale(listingOf(next))).toBe(true);
        expect(Array.map(next.credentials, ({ credential }) => credential)).toEqual([apiKey]);
        expect(isHeld(next)).toBe(true);
      }),
      Command.resolve(Announcer.Announce({ text: NOT_REFRESHED }), Message.CompletedAnnounce()),
    );
  });

  test("a deleted key's credential goes with it", () => {
    story(
      update,
      given(saving(showing(listed, apiKey))),
      message(Message.SucceededSaveChange({ change: deleteKey, maybeCredential: Option.none() })),
      model((next) => {
        expect(next.credentials).toEqual([]);
      }),
      Command.resolveAll(
        [listingQuery.Fetch, failedReadOf(SECOND_READ)],
        [Announcer.Announce({ text: "Key deleted." }), Message.CompletedAnnounce()],
      ),
      model((next) => {
        expect(AsyncData.isStale(listingOf(next))).toBe(true);
        expect(next.credentials).toEqual([]);
      }),
      Command.resolve(Announcer.Announce({ text: NOT_REFRESHED }), Message.CompletedAnnounce()),
    );
  });

  test("a stale listing is read again on request, and only then", () => {
    story(
      update,
      given(staleListed),
      message(Message.ClickedRetryListing()),
      Command.expectExact(listingQuery.Fetch({ generation: THIRD_READ })),
      model((next) => {
        expect(AsyncData.isRefreshing(listingOf(next))).toBe(true);
      }),
      Command.resolve(listingQuery.Fetch, readOf(THIRD_READ, listing)),
      model((next) => {
        expect(AsyncData.isSuccess(listingOf(next))).toBe(true);
        expect(isHeld(next)).toBe(false);
      }),
    );
  });

  test("a form is not opened while the dashboard is held", () => {
    story(
      update,
      given(rereading(listed)),
      message(Message.ClickedOpenForm({ form: Form.addResource() })),
      Command.expectNone(),
      model((next) => {
        expect(next.maybeForm).toEqual(Option.none());
      }),
    );
  });

  test("a refused sign-out says why on the page and can be tried again", () => {
    story(
      update,
      given(listed),
      message(Message.ClickedSignOut()),
      Command.expectExact(SignOut()),
      model((next) => {
        expect(next.activity).toEqual(Activity.SigningOut());
        expect(isHeld(next)).toBe(true);
      }),
      Command.resolve(SignOut, Message.FailedSignOut({ reason: "Fixture request failed" })),
      Command.resolve(Focus.Focus({ id: REFUSAL_ID }), Message.CompletedFocus()),
      model((next) => {
        expect(next.activity).toEqual(Activity.Idle());
        expect(Option.map(refusalAt(next, "Page"), ({ title }) => title)).toEqual(
          Option.some("Not signed out"),
        );
      }),
      message(Message.ClickedSignOut()),
      Command.resolve(SignOut, Message.SucceededSignOut()),
      model((next) => {
        expect(next.activity).toEqual(Activity.SigningOut());
      }),
    );
  });

  test("the sign-out waits for a change that is saving", () => {
    story(
      update,
      given(saving(listed)),
      message(Message.ClickedSignOut()),
      Command.expectNone(),
      model((next) => {
        expect(next.activity).toEqual(Activity.Saving());
      }),
    );
  });
});
