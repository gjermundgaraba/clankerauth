import {
  ConfirmDialog,
  CopyButton,
  Dialog,
} from "@gjermundgaraba-designs/pixel-paper";
import { Option, Schema } from "effect";
import { AsyncData } from "foldkit";
import { defineTaggedUnion } from "foldkit/schema";

import { Change, Credential, confirmationOf } from "./change.ts";
import type { Confirmation } from "./change.ts";
import * as Form from "./form.ts";
import { listingQuery } from "./listing.ts";
import type { Listing } from "./listing.ts";

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

export const Activity = defineTaggedUnion({
  Idle: {},
  Saving: {},
  SigningOut: {},
});

export type Activity = typeof Activity.Type;

/** What went wrong with a change or the sign-out, shown where it was asked for. */
export const Refusal = Schema.Struct({
  place: Place,
  title: Schema.String,
  reason: Schema.String,
});

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

export const listingOf = (model: Model): AsyncData.AsyncData<Listing, string> =>
  listingQuery.read(model.listing);

export const isSaving = (model: Model): boolean =>
  Activity.guards.Saving(model.activity);

export const isHeld = (model: Model): boolean =>
  !Activity.guards.Idle(model.activity) ||
  !AsyncData.isSuccess(listingOf(model));

export const isDialogOpen = (model: Model): boolean =>
  Dialog.isOpen(model.editor) || ConfirmDialog.isOpen(model.confirm);

export const refusalAt = (model: Model, place: Place): Option.Option<Refusal> =>
  Option.filter(model.maybeRefusal, (refusal) => refusal.place === place);

export const pendingConfirmation = (
  model: Model
): Option.Option<Confirmation> =>
  Option.flatMap(model.maybePending, confirmationOf);
