import type { Clipboard } from "@effect/platform-browser";
import {
  Announcer,
  Card,
  ConfirmDialog,
  CopyButton,
  Dialog,
  Focus,
} from "@gjermundgaraba-designs/pixel-paper";
import { Array, Option, Result } from "effect";
import { AsyncData } from "foldkit";
import { modifyFields } from "foldkit/struct";
import * as Update from "foldkit/update";

import type { Change, Credential } from "./change.ts";
import {
  announcementOf,
  confirmationOf,
  credentialId,
  isVoidedBy,
  needsReread,
} from "./change.ts";
import { SaveChange, SignOut } from "./command.ts";
import { EDITOR_FORM_ID, NOT_REFRESHED, REFUSAL_ID } from "./constant.ts";
import * as Form from "./form.ts";
import { listingQuery } from "./listing.ts";
import { Message } from "./message.ts";
import { Activity, isHeld, isSaving, listingOf } from "./model.ts";
import type { Model, PendingCredential, Place, Refusal } from "./model.ts";

// LISTING

const listing = listingQuery.lift<Model, Message>({
  parentField: "listing",
  toParentMessage: (message) => Message.GotListingMessage({ message }),
});

// INIT

export const init = (): Update.Return<Model, Message> =>
  listing.loadIfMissing({
    listing: listingQuery.init(),
    credentials: [],
    issuerCopy: CopyButton.init({ id: "copy-issuer" }),
    editor: Dialog.init({ id: "dashboard-editor" }),
    maybeForm: Option.none(),
    confirm: ConfirmDialog.init({ id: "dashboard-confirm" }),
    maybePending: Option.none(),
    activity: Activity.Idle(),
    maybeRefusal: Option.none(),
  });

// UPDATE

type UpdateReturn = Update.Return<Model, Message>;

const editorFold = Dialog.foldDialog(Dialog, {
  read: (model: Model) => model.editor,
  write: (model: Model, nextEditor: Dialog.Model): Model =>
    modifyFields(model, { editor: () => nextEditor }),
  toParentMessage: (message: Dialog.Message) =>
    Message.GotEditorMessage({ message }),
  isCloseHeld: isSaving,
});

const withoutRefusalAt = (model: Model, place: Place): Model =>
  modifyFields(model, {
    maybeRefusal: Option.filter((refusal: Refusal) => refusal.place !== place),
  });

const placeOf = (model: Model): Place => {
  if (ConfirmDialog.isOpen(model.confirm)) {
    return "Confirm";
  }

  if (Dialog.isOpen(model.editor)) {
    return "Editor";
  }

  return "Page";
};

const saving = (model: Model, change: Change): UpdateReturn => ({
  model: modifyFields(model, {
    activity: () => Activity.Saving(),
    maybeRefusal: () => Option.none(),
  }),
  commands: [
    ...(placeOf(model) === "Editor"
      ? [Focus.Focus({ id: Card.submitId(EDITOR_FORM_ID) })]
      : []),
    SaveChange({ change }),
  ],
});

const foldConfirmOutMessage = ConfirmDialog.OutMessage.match<
  Update.Step<Model, Message>
>({
  Confirmed: () => (stepModel) =>
    Option.match(stepModel.maybePending, {
      onNone: () => ({ model: stepModel }),
      onSome: (change) =>
        Activity.guards.Idle(stepModel.activity)
          ? saving(stepModel, change)
          : { model: stepModel },
    }),
  Cancelled: () => (stepModel) => ({ model: stepModel }),
});

const confirmFold = {
  read: (model: Model) => Option.some(model.confirm),
  write: (model: Model, nextConfirm: ConfirmDialog.Model): Model =>
    modifyFields(model, { confirm: () => nextConfirm }),
  toParentMessage: (message: ConfirmDialog.Message) =>
    Message.GotConfirmMessage({ message }),
  foldOutMessage: foldConfirmOutMessage,
};

const foldConfirm = (model: Model, message: ConfirmDialog.Message) =>
  Update.foldChild({
    update: (
      confirm: ConfirmDialog.Model,
      confirmMessage: ConfirmDialog.Message
    ) =>
      ConfirmDialog.update(confirm, confirmMessage, {
        isCloseHeld: isSaving(model),
      }),
    ...confirmFold,
  })(model, message);

const foldConfirmOpen = Update.foldChildStep({
  update: ConfirmDialog.open,
  ...confirmFold,
});

const foldConfirmClose = Update.foldChildStep({
  update: ConfirmDialog.close,
  ...confirmFold,
});

const foldIssuerCopy = Update.foldChild({
  update: CopyButton.update,
  read: (model: Model) => Option.some(model.issuerCopy),
  write: (model: Model, nextCopy: CopyButton.Model): Model =>
    modifyFields(model, { issuerCopy: () => nextCopy }),
  toParentMessage: (message: CopyButton.Message) =>
    Message.GotIssuerCopyMessage({ message }),
});

const isCredential = (id: string) => (pending: PendingCredential) =>
  credentialId(pending.credential) === id;

const foldCredentialCopy = Update.foldChildAt({
  update: CopyButton.update,
  readAt: (model: Model, id: string) =>
    Option.map(
      Array.findFirst(model.credentials, isCredential(id)),
      ({ copy }) => copy
    ),
  writeAt: (model: Model, id: string, nextCopy: CopyButton.Model): Model =>
    modifyFields(model, {
      credentials: Array.map((pending) =>
        isCredential(id)(pending)
          ? modifyFields(pending, { copy: () => nextCopy })
          : pending
      ),
    }),
  toParentMessage: (id: string, message: CopyButton.Message) =>
    Message.GotCredentialCopyMessage({ credentialId: id, message }),
});

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
          "Confirm"
        )
      ),
  });
};

const copyIdOf = (credential: Credential): string =>
  `copy-${credentialId(credential)}`;

const credentialsAfter = (
  credentials: readonly PendingCredential[],
  change: Change,
  maybeCredential: Option.Option<Credential>
): readonly PendingCredential[] => {
  const kept = Array.filter(
    credentials,
    ({ credential }) =>
      !isVoidedBy(change, credential) &&
      !Option.exists(
        maybeCredential,
        (shown) => credentialId(shown) === credentialId(credential)
      )
  );

  return Array.appendAll(
    kept,
    Option.toArray(
      Option.map(maybeCredential, (credential) => ({
        credential,
        copy: CopyButton.init({ id: copyIdOf(credential) }),
      }))
    )
  );
};

const closeEditor = (model: Model): UpdateReturn =>
  Dialog.isOpen(model.editor) ? editorFold.close(model) : { model };

const closeConfirm = (model: Model): UpdateReturn =>
  ConfirmDialog.isOpen(model.confirm) ? foldConfirmClose(model) : { model };

const saved = (
  model: Model,
  change: Change,
  maybeCredential: Option.Option<Credential>
): UpdateReturn =>
  Update.combine(
    modifyFields(model, {
      activity: () => Activity.Idle(),
      credentials: (credentials) =>
        credentialsAfter(credentials, change, maybeCredential),
    }),
    [
      closeEditor,
      closeConfirm,
      ...(needsReread(change) ? [listing.revalidateOrLoad] : []),
      (stepModel) => ({
        model: stepModel,
        commands: [
          Announcer.Announce({ text: announcementOf(change) }),
          ...Array.fromOption(
            Option.map(maybeCredential, (credential) =>
              Focus.Focus({ id: copyIdOf(credential) })
            )
          ),
        ],
      }),
    ]
  );

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

const resourceIdentifiers = (model: Model): readonly string[] =>
  Option.match(AsyncData.getData(listingOf(model)), {
    onNone: () => [],
    onSome: ({ overview }) =>
      Array.map(overview.resources, ({ identifier }) => identifier),
  });

const submitted = (model: Model): UpdateReturn =>
  Option.match(model.maybeForm, {
    onNone: () => ({ model }),
    onSome: (form) =>
      Result.match(Form.changeOf(form, resourceIdentifiers(model)), {
        onFailure: (reason) => ({
          model: modifyFields(model, {
            maybeRefusal: () =>
              Option.some<Refusal>({
                place: "Editor",
                title: "Not saved",
                reason,
              }),
          }),
        }),
        onSuccess: (change) => requested(model, change),
      }),
  });

const formOpened = (model: Model, form: Form.Model): UpdateReturn =>
  isHeld(model)
    ? { model }
    : editorFold.open(
        withoutRefusalAt(
          modifyFields(model, { maybeForm: () => Option.some(form) }),
          "Editor"
        )
      );

export const update = (model: Model, message: Message) =>
  Message.match<Update.Return<Model, Message, Clipboard.Clipboard>>(message, {
    GotListingMessage: ({ message: listingMessage }) => {
      const listingFold = listing.fold(model, listingMessage);

      return !AsyncData.isStale(listingOf(model)) &&
        AsyncData.isStale(listingOf(listingFold.model))
        ? {
            model: listingFold.model,
            commands: [
              ...(listingFold.commands ?? []),
              Announcer.Announce({ text: NOT_REFRESHED }),
            ],
          }
        : listingFold;
    },
    ClickedRetryListing: () => listing.revalidateOrLoad(model),
    ClickedOpenForm: ({ form }) => formOpened(model, form),
    GotFormMessage: ({ message: formMessage }) => ({
      model: modifyFields(model, {
        maybeForm: Option.map((form) => Form.update(form, formMessage)),
      }),
    }),
    SubmittedForm: () => submitted(model),
    ClickedChange: ({ change }) => requested(model, change),
    SucceededSaveChange: ({ change, maybeCredential }) =>
      saved(model, change, maybeCredential),
    FailedSaveChange: ({ reason }) => refused(model, reason),
    ClickedDismissCredentials: () => ({
      model: modifyFields(model, { credentials: () => [] }),
    }),
    ClickedSignOut: () =>
      Activity.guards.Idle(model.activity)
        ? {
            model: modifyFields(model, {
              activity: () => Activity.SigningOut(),
            }),
            commands: [SignOut()],
          }
        : { model },
    SucceededSignOut: () => ({ model }),
    FailedSignOut: ({ reason }) => ({
      model: modifyFields(model, {
        activity: () => Activity.Idle(),
        maybeRefusal: () =>
          Option.some<Refusal>({
            place: "Page",
            title: "Not signed out",
            reason,
          }),
      }),
      commands: [Focus.Focus({ id: REFUSAL_ID })],
    }),
    GotEditorMessage: ({ message: editorMessage }) =>
      editorFold.update(model, editorMessage),
    GotConfirmMessage: ({ message: confirmMessage }) =>
      foldConfirm(model, confirmMessage),
    GotCredentialCopyMessage: ({ credentialId: id, message: copyMessage }) =>
      foldCredentialCopy(model, id, copyMessage),
    GotIssuerCopyMessage: ({ message: copyMessage }) =>
      foldIssuerCopy(model, copyMessage),
    GotTopBarMessage: () => ({ model }),
    CompletedAnnounce: () => ({ model }),
    CompletedFocus: () => ({ model }),
  });
