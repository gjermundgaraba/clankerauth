import { MAXIMUM_PASSWORD_LENGTH, MINIMUM_PASSWORD_LENGTH } from "@clankerauth/admin-api";
import { Boolean, Effect, Match, Option, Schema } from "effect";
import { Command } from "foldkit";
import type { Html, HtmlBuilder } from "foldkit/html";
import { defineMessageUnion } from "foldkit/message";
import { defineTaggedUnion } from "foldkit/schema";
import { modifyFields } from "foldkit/struct";
import { defineView } from "foldkit/submodel";
import type * as Update from "foldkit/update";
import {
  Button,
  Field,
  Fields,
  Focus,
  Notice,
  PasswordField,
} from "@gjermundgaraba-designs/pixel-paper";

import { issuer, toOwnerSentence } from "../api.ts";
import { wallCardView } from "./wall.ts";

// MODEL

const SetupField = Schema.Literals(["Email", "Password", "Confirmation"]);

type SetupField = typeof SetupField.Type;

export const Problem = defineTaggedUnion({
  Invalid: { field: SetupField },
  Refused: { reason: Schema.String },
});

type Problem = typeof Problem.Type;

export const Model = Schema.Struct({
  email: Schema.String,
  password: Schema.String,
  confirmation: Schema.String,
  isPasswordShown: Schema.Boolean,
  isConfirmationShown: Schema.Boolean,
  isCreating: Schema.Boolean,
  maybeProblem: Schema.Option(Problem),
});

export type Model = typeof Model.Type;

// MESSAGE

const Outcome = Schema.Literals(["Created", "AlreadyOwned"]);

type Outcome = typeof Outcome.Type;

export const Message = defineMessageUnion({
  UpdatedEmail: { value: Schema.String },
  UpdatedPassword: { value: Schema.String },
  UpdatedConfirmation: { value: Schema.String },
  ToggledPasswordShown: {},
  ToggledConfirmationShown: {},
  SubmittedSetup: {},
  SucceededSetupOwner: { outcome: Outcome },
  FailedSetupOwner: { reason: Schema.String },
  CompletedFocus: {},
});

export type Message = typeof Message.Type;

// OUT MESSAGE

/** `CreatedOwner`: the owner exists and is signed in. `FoundOwner`: someone set the issuer up
 *  first, so the owner signs in instead. */
export const OutMessage = defineMessageUnion({
  CreatedOwner: {},
  FoundOwner: {},
});

export type OutMessage = typeof OutMessage.Type;

// INIT

export const init = (): Model => ({
  email: "",
  password: "",
  confirmation: "",
  isPasswordShown: false,
  isConfirmationShown: false,
  isCreating: false,
  maybeProblem: Option.none(),
});

// COMMAND

export const SetupOwner = Command.define("SetupOwner", {
  args: { email: Schema.String, password: Schema.String },
  messages: [Message.SucceededSetupOwner, Message.FailedSetupOwner],
  execute: ({ email, password }) =>
    issuer.setupOwner({ email, password }).pipe(
      Effect.map((): Outcome => "Created"),
      Effect.catchTag("Conflict", () => Effect.succeed<Outcome>("AlreadyOwned")),
      toOwnerSentence,
      Effect.match({
        onFailure: (reason) => Message.FailedSetupOwner({ reason }),
        onSuccess: (outcome) => Message.SucceededSetupOwner({ outcome }),
      }),
    ),
});

// UPDATE

const FIELD_IDS: Readonly<Record<SetupField, string>> = {
  Email: "setup-email",
  Password: "setup-password",
  Confirmation: "setup-confirmation",
};

const invalidFieldOf = (model: Model): Option.Option<SetupField> => {
  if (model.email.trim() === "") {
    return Option.some("Email");
  }

  if (
    model.password.length < MINIMUM_PASSWORD_LENGTH ||
    model.password.length > MAXIMUM_PASSWORD_LENGTH
  ) {
    return Option.some("Password");
  }

  if (model.password !== model.confirmation) {
    return Option.some("Confirmation");
  }

  return Option.none();
};

const submitted = (model: Model): Update.Return<Model, Message> =>
  Option.match(invalidFieldOf(model), {
    onNone: () => ({
      model: modifyFields(model, {
        isCreating: () => true,
        isPasswordShown: () => false,
        isConfirmationShown: () => false,
        maybeProblem: () => Option.none(),
      }),
      commands: [SetupOwner({ email: model.email.trim(), password: model.password })],
    }),
    onSome: (field) => ({
      model: modifyFields(model, { maybeProblem: () => Option.some(Problem.Invalid({ field })) }),
      commands: [Focus.Focus({ id: FIELD_IDS[field] })],
    }),
  });

export const update = (model: Model, message: Message) =>
  Message.match<Update.ReturnWithOutMessage<Model, Message, OutMessage>>(message, {
    UpdatedEmail: ({ value }) => ({ model: modifyFields(model, { email: () => value }) }),
    UpdatedPassword: ({ value }) => ({ model: modifyFields(model, { password: () => value }) }),
    UpdatedConfirmation: ({ value }) => ({
      model: modifyFields(model, { confirmation: () => value }),
    }),
    ToggledPasswordShown: () => ({
      model: modifyFields(model, { isPasswordShown: Boolean.not }),
    }),
    ToggledConfirmationShown: () => ({
      model: modifyFields(model, { isConfirmationShown: Boolean.not }),
    }),
    SubmittedSetup: () => (model.isCreating ? { model } : submitted(model)),
    SucceededSetupOwner: ({ outcome }) => ({
      model,
      outMessage: Match.value(outcome).pipe(
        Match.withReturnType<OutMessage>(),
        Match.when("Created", () => OutMessage.CreatedOwner()),
        Match.when("AlreadyOwned", () => OutMessage.FoundOwner()),
        Match.exhaustive,
      ),
    }),
    FailedSetupOwner: ({ reason }) => ({
      model: modifyFields(model, {
        isCreating: () => false,
        maybeProblem: () => Option.some(Problem.Refused({ reason })),
      }),
    }),
    CompletedFocus: () => ({ model }),
  });

// VIEW

const INVALID_SENTENCES: Readonly<Record<SetupField, string>> = {
  Email: "Enter the owner's email address.",
  Password: `Use a password between ${MINIMUM_PASSWORD_LENGTH} and ${MAXIMUM_PASSWORD_LENGTH} characters.`,
  Confirmation: "Passwords do not match.",
};

const problemView = (problem: Problem, h: HtmlBuilder<Message>): Html =>
  Notice.view(
    {
      tone: "Error",
      title: "Not created",
      body: [
        Problem.match(problem, {
          Invalid: ({ field }) => INVALID_SENTENCES[field],
          Refused: ({ reason }) => reason,
        }),
      ],
    },
    h,
  );

const isInvalid = (model: Model, field: SetupField): boolean =>
  Option.exists(model.maybeProblem, (problem) =>
    Problem.matchOrElse(problem, { Invalid: (invalid) => invalid.field === field }, () => false),
  );

export const view = defineView<Model, Message>((model, h): Html =>
  wallCardView(
    "Set up clankerauth",
    {
      title: "Setup",
      meta: "first run",
      onSubmit: Message.SubmittedSetup(),
      actions: [
        Button.view(
          {
            label: "create account",
            type: "submit",
            variant: "Primary",
            isDefault: true,
            isBusy: model.isCreating,
          },
          h,
        ),
      ],
      body: [
        h.p(
          [h.Class("note-line")],
          [
            "Create the owner account for your private applications. It manages Clients and Resources and approves access, and it stays on your infrastructure.",
          ],
        ),
        ...Option.toArray(Option.map(model.maybeProblem, (problem) => problemView(problem, h))),
        Fields.view(
          {
            isBusy: model.isCreating,
            body: [
              Field.view(
                {
                  id: FIELD_IDS.Email,
                  label: "Email",
                  type: "email",
                  value: model.email,
                  onInput: (value) => Message.UpdatedEmail({ value }),
                  isBoxed: true,
                  isRequired: true,
                  isInvalid: isInvalid(model, "Email"),
                  inputAttributes: [
                    h.Autocomplete("username"),
                    h.Placeholder("owner@example.internal"),
                  ],
                },
                h,
              ),
              PasswordField.view(
                {
                  id: FIELD_IDS.Password,
                  label: "Password",
                  value: model.password,
                  onInput: (value) => Message.UpdatedPassword({ value }),
                  isShown: model.isPasswordShown,
                  onToggleShown: Message.ToggledPasswordShown(),
                  isRequired: true,
                  isInvalid: isInvalid(model, "Password"),
                  help: `Use ${MINIMUM_PASSWORD_LENGTH}–${MAXIMUM_PASSWORD_LENGTH} characters. Save your password somewhere safe.`,
                  autocomplete: "new-password",
                },
                h,
              ),
              PasswordField.view(
                {
                  id: FIELD_IDS.Confirmation,
                  label: "Confirm password",
                  value: model.confirmation,
                  onInput: (value) => Message.UpdatedConfirmation({ value }),
                  isShown: model.isConfirmationShown,
                  onToggleShown: Message.ToggledConfirmationShown(),
                  isRequired: true,
                  isInvalid: isInvalid(model, "Confirmation"),
                  autocomplete: "new-password",
                },
                h,
              ),
            ],
          },
          h,
        ),
      ],
    },
    h,
  ),
);
