import type { Clipboard } from "@effect/platform-browser";
import { Array, Option, Result } from "effect";
import { AsyncData } from "foldkit";
import { modifyFields } from "foldkit/struct";
import * as Update from "foldkit/update";
import { ConfirmDialog, CopyButton, Dialog, Focus } from "@gjermundgaraba-designs/pixel-paper";

import {
  Change,
  announcementOf,
  confirmationOf,
  credentialId,
  isVoidedBy,
  needsReread,
  type Credential,
} from "./change.ts";
import { Announce, FetchListing, SaveChange, SignOut } from "./command.ts";
import { NOT_REFRESHED, REFUSAL_ID } from "./constant.ts";
import * as Form from "./form.ts";
import { Message } from "./message.ts";
import {
  Activity,
  ListingData,
  type Model,
  type PendingCredential,
  type Place,
  type Refusal,
  isHeld,
  isSaving,
} from "./model.ts";

// INIT

export const init = (): Update.Return<Model, Message> => ({
  model: {
    listing: ListingData.Loading(),
    credentials: [],
    issuerCopy: CopyButton.init({ id: "copy-issuer" }),
    editor: Dialog.init({ id: "dashboard-editor" }),
    maybeForm: Option.none(),
    confirm: ConfirmDialog.init({ id: "dashboard-confirm" }),
    maybePending: Option.none(),
    activity: Activity.Idle(),
    maybeRefusal: Option.none(),
  },
  commands: [FetchListing()],
});

// UPDATE

type UpdateReturn = Update.Return<Model, Message>;

const editorFold = Dialog.foldDialog(Dialog, {
  read: (model: Model) => model.editor,
  write: (model: Model, nextEditor: Dialog.Model): Model =>
    modifyFields(model, { editor: () => nextEditor }),
  toParentMessage: (message: Dialog.Message) => Message.GotEditorMessage({ message }),
});

/** Reads the listing again: afresh after a failed first read, in place once it has data. A
 *  read already running is left to finish. */
const reloadListing = Update.refresh({
  read: (model: Model) => Option.some(model.listing),
  revalidate: AsyncData.revalidateOrLoad,
  write: (model, nextListing) => modifyFields(model, { listing: () => nextListing }),
  load: FetchListing(),
});

/** Drops a refusal shown at `place`, which a fresh start there makes old news. */
const withoutRefusalAt = (model: Model, place: Place): Model =>
  modifyFields(model, {
    maybeRefusal: Option.filter((refusal: Refusal) => refusal.place !== place),
  });

/** Saves a change; whatever was refused before no longer applies. */
const saving = (model: Model, change: Change): UpdateReturn => ({
  model: modifyFields(model, {
    activity: () => Activity.Saving(),
    maybeRefusal: () => Option.none(),
  }),
  commands: [SaveChange({ change })],
});

const foldConfirmOutMessage = ConfirmDialog.OutMessage.match<Update.Step<Model, Message>>({
  Confirmed: () => (stepModel) =>
    Option.match(stepModel.maybePending, {
      onNone: () => ({ model: stepModel }),
      onSome: (change) =>
        Activity.guards.Idle(stepModel.activity) ? saving(stepModel, change) : { model: stepModel },
    }),
  Cancelled: () => (stepModel) => ({ model: stepModel }),
});

const confirmFold = {
  read: (model: Model) => Option.some(model.confirm),
  write: (model: Model, nextConfirm: ConfirmDialog.Model): Model =>
    modifyFields(model, { confirm: () => nextConfirm }),
  toParentMessage: (message: ConfirmDialog.Message) => Message.GotConfirmMessage({ message }),
  foldOutMessage: foldConfirmOutMessage,
};

const foldConfirm = Update.foldChild({ update: ConfirmDialog.update, ...confirmFold });

const foldConfirmOpen = Update.foldChildStep({ update: ConfirmDialog.open, ...confirmFold });

const foldConfirmClose = Update.foldChildStep({ update: ConfirmDialog.close, ...confirmFold });

const foldIssuerCopy = Update.foldChild({
  update: CopyButton.update,
  read: (model: Model) => Option.some(model.issuerCopy),
  write: (model: Model, nextCopy: CopyButton.Model): Model =>
    modifyFields(model, { issuerCopy: () => nextCopy }),
  toParentMessage: (message: CopyButton.Message) => Message.GotIssuerCopyMessage({ message }),
});

const isCredential = (id: string) => (pending: PendingCredential) =>
  credentialId(pending.credential) === id;

const foldCredentialCopy = Update.foldChildAt({
  update: CopyButton.update,
  readAt: (model: Model, id: string) =>
    Option.map(Array.findFirst(model.credentials, isCredential(id)), ({ copy }) => copy),
  writeAt: (model: Model, id: string, nextCopy: CopyButton.Model): Model =>
    modifyFields(model, {
      credentials: Array.map((pending) =>
        isCredential(id)(pending) ? modifyFields(pending, { copy: () => nextCopy }) : pending,
      ),
    }),
  toParentMessage: (id: string, message: CopyButton.Message) =>
    Message.GotCredentialCopyMessage({ credentialId: id, message }),
});

/** A change is saved at once, or asked about first when it revokes or destroys something. */
const requested = (model: Model, change: Change): UpdateReturn => {
  if (isHeld(model)) {
    return { model };
  }

  return Option.match(confirmationOf(change), {
    onNone: () => saving(model, change),
    onSome: () =>
      foldConfirmOpen(
        withoutRefusalAt(
          modifyFields(model, { maybePending: () => Option.some(change) }),
          "Confirm",
        ),
      ),
  });
};

const copyIdOf = (credential: Credential): string => `copy-${credentialId(credential)}`;

/** The credentials after a saved change: what it voided goes, and what it shows replaces any
 *  shown before for the same thing. */
const credentialsAfter = (
  credentials: ReadonlyArray<PendingCredential>,
  change: Change,
  maybeCredential: Option.Option<Credential>,
): ReadonlyArray<PendingCredential> => {
  const kept = Array.filter(
    credentials,
    ({ credential }) =>
      !isVoidedBy(change, credential) &&
      !Option.exists(maybeCredential, (shown) => credentialId(shown) === credentialId(credential)),
  );

  return Array.appendAll(
    kept,
    Option.toArray(
      Option.map(maybeCredential, (credential) => ({
        credential,
        copy: CopyButton.init({ id: copyIdOf(credential) }),
      })),
    ),
  );
};

const closeEditor = (model: Model): UpdateReturn =>
  Dialog.isOpen(model.editor) ? editorFold.close(model) : { model };

const closeConfirm = (model: Model): UpdateReturn =>
  ConfirmDialog.isOpen(model.confirm) ? foldConfirmClose(model) : { model };

const saved = (
  model: Model,
  change: Change,
  maybeCredential: Option.Option<Credential>,
): UpdateReturn =>
  Update.combine(
    modifyFields(model, {
      activity: () => Activity.Idle(),
      credentials: (credentials) => credentialsAfter(credentials, change, maybeCredential),
    }),
    [
      closeEditor,
      closeConfirm,
      ...(needsReread(change) ? [reloadListing] : []),
      (stepModel) => ({
        model: stepModel,
        commands: [
          Announce({ text: announcementOf(change) }),
          ...Array.fromOption(
            Option.map(maybeCredential, (credential) => Focus.Focus({ id: copyIdOf(credential) })),
          ),
        ],
      }),
    ],
  );

/** Where a saving change was asked for: the dialog it was asked in, which stays open while it
 *  saves, or else the page. */
const placeOf = (model: Model): Place => {
  if (ConfirmDialog.isOpen(model.confirm)) {
    return "Confirm";
  }

  if (Dialog.isOpen(model.editor)) {
    return "Editor";
  }

  return "Page";
};

/** A refusal lands where the change was asked for: in its dialog, or on the page, where the
 *  notice takes focus so it is read. */
const refused = (model: Model, reason: string): UpdateReturn => {
  const place = placeOf(model);

  const nextModel = modifyFields(model, {
    activity: () => Activity.Idle(),
    maybeRefusal: () => Option.some({ place, title: "Not saved", reason }),
  });

  return place === "Page"
    ? { model: nextModel, commands: [Focus.Focus({ id: REFUSAL_ID })] }
    : { model: nextModel };
};

const submitted = (model: Model): UpdateReturn =>
  Option.match(model.maybeForm, {
    onNone: () => ({ model }),
    onSome: (form) =>
      Result.match(Form.changeOf(form), {
        onFailure: (reason) => ({
          model: modifyFields(model, {
            maybeRefusal: () =>
              Option.some<Refusal>({ place: "Editor", title: "Not saved", reason }),
          }),
        }),
        onSuccess: (change) => requested(model, change),
      }),
  });

const formOpened = (model: Model, form: Form.Model): UpdateReturn =>
  isHeld(model)
    ? { model }
    : editorFold.open(
        withoutRefusalAt(modifyFields(model, { maybeForm: () => Option.some(form) }), "Editor"),
      );

// The copy buttons write through the application's `Clipboard` service.
export const update = (model: Model, message: Message) =>
  Message.match<Update.Return<Model, Message, Clipboard.Clipboard>>(message, {
    SettledFetchListing: ({ result }) => {
      const nextModel = modifyFields(model, { listing: AsyncData.settle(result) });

      return AsyncData.isStale(nextModel.listing)
        ? { model: nextModel, commands: [Announce({ text: NOT_REFRESHED })] }
        : { model: nextModel };
    },
    ClickedRetryListing: () => reloadListing(model),
    ClickedOpenForm: ({ form }) => formOpened(model, form),
    GotFormMessage: ({ message: formMessage }) => ({
      model: modifyFields(model, {
        maybeForm: Option.map((form) => Form.update(form, formMessage)),
      }),
    }),
    SubmittedForm: () => submitted(model),
    ClickedChange: ({ change }) => requested(model, change),
    SucceededSaveChange: ({ change, maybeCredential }) => saved(model, change, maybeCredential),
    FailedSaveChange: ({ reason }) => refused(model, reason),
    ClickedDismissCredentials: () => ({ model: modifyFields(model, { credentials: () => [] }) }),
    ClickedSignOut: () =>
      Activity.guards.Idle(model.activity)
        ? {
            model: modifyFields(model, { activity: () => Activity.SigningOut() }),
            commands: [SignOut()],
          }
        : { model },
    // The page is on its way to the sign-in, which reads the session again.
    SucceededSignOut: () => ({ model }),
    FailedSignOut: ({ reason }) => ({
      model: modifyFields(model, {
        activity: () => Activity.Idle(),
        maybeRefusal: () =>
          Option.some<Refusal>({ place: "Page", title: "Not signed out", reason }),
      }),
      commands: [Focus.Focus({ id: REFUSAL_ID })],
    }),
    // NOTE: while a change saves, its dialog stays open so the result lands where it was
    // asked for: Escape, the veil and the close glyph all ask to close it.
    GotEditorMessage: ({ message: editorMessage }) =>
      isSaving(model) && Dialog.isCloseRequest(editorMessage)
        ? { model }
        : editorFold.update(model, editorMessage),
    GotConfirmMessage: ({ message: confirmMessage }) => foldConfirm(model, confirmMessage),
    GotCredentialCopyMessage: ({ credentialId: id, message: copyMessage }) =>
      foldCredentialCopy(model, id, copyMessage),
    GotIssuerCopyMessage: ({ message: copyMessage }) => foldIssuerCopy(model, copyMessage),
    GotTopBarMessage: () => ({ model }),
    CompletedAnnounce: () => ({ model }),
    CompletedFocus: () => ({ model }),
  });
