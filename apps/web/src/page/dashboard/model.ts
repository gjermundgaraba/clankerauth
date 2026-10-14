import { Option, Schema } from "effect";
import { AsyncData } from "foldkit";
import { defineTaggedUnion } from "foldkit/schema";
import { ConfirmDialog, CopyButton, Dialog } from "@gjermundgaraba-designs/pixel-paper";

import { Change, type Confirmation, Credential, confirmationOf } from "./change.ts";
import * as Form from "./form.ts";
import { type Listing, listingQuery } from "./listing.ts";

// MODEL

/** A credential shown once, with the button that copies it. */
export const PendingCredential = Schema.Struct({
  credential: Credential,
  copy: CopyButton.Model,
});

export type PendingCredential = typeof PendingCredential.Type;

/** Where a change was asked for, which is where its refusal is shown. */
export const Place = Schema.Literals(["Page", "Editor", "Confirm"]);

export type Place = typeof Place.Type;

/** What the dashboard is doing: nothing, saving a change, or signing out. Only one at a time,
 *  and nothing else is offered while one runs. */
export const Activity = defineTaggedUnion({
  Idle: {},
  Saving: {},
  SigningOut: {},
});

export type Activity = typeof Activity.Type;

/** What went wrong with a change or the sign-out, shown where it was asked for. */
export const Refusal = Schema.Struct({ place: Place, title: Schema.String, reason: Schema.String });

export type Refusal = typeof Refusal.Type;

export const Model = Schema.Struct({
  listing: listingQuery.Model,
  credentials: Schema.Array(PendingCredential),
  issuerCopy: CopyButton.Model,
  editor: Dialog.Model,
  /** What the editor shows. Kept after it closes, so it closes on what it showed. */
  maybeForm: Schema.Option(Form.Model),
  confirm: ConfirmDialog.Model,
  /** The change the confirmation asks about, kept after it closes the same way. */
  maybePending: Schema.Option(Change),
  activity: Activity,
  maybeRefusal: Schema.Option(Refusal),
});

export type Model = typeof Model.Type;

// ACCESSORS

/** The listing as the dashboard has read it. */
export const listingOf = (model: Model): AsyncData.AsyncData<Listing, string> =>
  listingQuery.read(model.listing);

/** Whether a change is saving, so its dialog stays open and its controls are busy. */
export const isSaving = (model: Model): boolean => Activity.guards.Saving(model.activity);

/**
 * Whether every change is held: one is saving, the sign-out runs, the listing is being read
 * again, or the last read failed after a save. A save is never offered again on a listing that
 * may be out of date, so the only way on from a failed read is to read again.
 */
export const isHeld = (model: Model): boolean =>
  !Activity.guards.Idle(model.activity) || !AsyncData.isSuccess(listingOf(model));

/** Whether one of the dashboard's dialogs is open, so it hosts the page's live region. */
export const isDialogOpen = (model: Model): boolean =>
  Dialog.isOpen(model.editor) || ConfirmDialog.isOpen(model.confirm);

/** The refusal to show at `place`, if the last one was refused there. */
export const refusalAt = (model: Model, place: Place): Option.Option<Refusal> =>
  Option.filter(model.maybeRefusal, (refusal) => refusal.place === place);

/** What the confirmation asks about the pending change, for the dialog's words. */
export const pendingConfirmation = (model: Model): Option.Option<Confirmation> =>
  Option.flatMap(model.maybePending, confirmationOf);
