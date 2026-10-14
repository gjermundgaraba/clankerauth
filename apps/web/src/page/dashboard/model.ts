import { Option, Schema } from "effect";
import { AsyncData } from "foldkit";
import { defineTaggedUnion } from "foldkit/schema";
import { ConfirmDialog, CopyButton, Dialog } from "@gjermundgaraba-designs/pixel-paper";

import { Change, type Confirmation, Credential, confirmationOf } from "./change.ts";
import * as Form from "./form.ts";
import { type Listing, listingQuery } from "./listing.ts";

// MODEL

export const PendingCredential = Schema.Struct({
  credential: Credential,
  copy: CopyButton.Model,
});

export type PendingCredential = typeof PendingCredential.Type;

export const Place = Schema.Literals(["Page", "Editor", "Confirm"]);

export type Place = typeof Place.Type;

export const Activity = defineTaggedUnion({
  Idle: {},
  Saving: {},
  SigningOut: {},
});

export type Activity = typeof Activity.Type;

export const Refusal = Schema.Struct({ place: Place, title: Schema.String, reason: Schema.String });

export type Refusal = typeof Refusal.Type;

export const Model = Schema.Struct({
  listing: listingQuery.Model,
  credentials: Schema.Array(PendingCredential),
  issuerCopy: CopyButton.Model,
  editor: Dialog.Model,
  maybeForm: Schema.Option(Form.Model),
  confirm: ConfirmDialog.Model,
  maybePending: Schema.Option(Change),
  activity: Activity,
  maybeRefusal: Schema.Option(Refusal),
});

export type Model = typeof Model.Type;

// ACCESSORS

export const listingOf = (model: Model): AsyncData.AsyncData<Listing, string> =>
  listingQuery.read(model.listing);

export const isSaving = (model: Model): boolean => Activity.guards.Saving(model.activity);

export const isHeld = (model: Model): boolean =>
  !Activity.guards.Idle(model.activity) || !AsyncData.isSuccess(listingOf(model));

export const isDialogOpen = (model: Model): boolean =>
  Dialog.isOpen(model.editor) || ConfirmDialog.isOpen(model.confirm);

export const refusalAt = (model: Model, place: Place): Option.Option<Refusal> =>
  Option.filter(model.maybeRefusal, (refusal) => refusal.place === place);

export const pendingConfirmation = (model: Model): Option.Option<Confirmation> =>
  Option.flatMap(model.maybePending, confirmationOf);
