import { Schema } from "effect";
import { defineMessageUnion } from "foldkit/message";
import { ConfirmDialog, CopyButton, Dialog, TopBar } from "@gjermundgaraba-designs/pixel-paper";

import { Change, Credential } from "./change.ts";
import * as Form from "./form.ts";
import { Listing } from "./model.ts";

export const Message = defineMessageUnion({
  SettledFetchListing: { result: Schema.Result(Listing, Schema.String) },
  ClickedRetryListing: {},
  ClickedOpenForm: { form: Form.Model },
  GotFormMessage: { message: Form.Message },
  SubmittedForm: {},
  ClickedChange: { change: Change },
  SucceededSaveChange: { change: Change, maybeCredential: Schema.Option(Credential) },
  FailedSaveChange: { reason: Schema.String },
  ClickedDismissCredentials: {},
  ClickedSignOut: {},
  SucceededSignOut: {},
  FailedSignOut: { reason: Schema.String },
  GotEditorMessage: { message: Dialog.Message },
  GotConfirmMessage: { message: ConfirmDialog.Message },
  GotCredentialCopyMessage: { credentialId: Schema.String, message: CopyButton.Message },
  GotIssuerCopyMessage: { message: CopyButton.Message },
  GotTopBarMessage: { message: TopBar.Message },
  CompletedAnnounce: {},
  CompletedFocus: {},
});

export type Message = typeof Message.Type;
