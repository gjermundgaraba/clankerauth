import {
  Card,
  Field,
  Focus,
  Notice,
  PasswordField,
} from "@gjermundgaraba-designs/pixel-paper";
import { passwordRule } from "@gjermundgaraba/clankerauth-admin-api";
import type * as Action from "@gjermundgaraba/effect-actions/Action";
import { Array, Boolean, Effect, Match, Option, Schema } from "effect";
import { Command } from "foldkit";
import type { Html, HtmlBuilder } from "foldkit/html";
import { defineMessageUnion } from "foldkit/message";
import { defineTaggedUnion } from "foldkit/schema";
import { modifyFields } from "foldkit/struct";
import { defineView } from "foldkit/submodel";
import type * as Update from "foldkit/update";

import { issuer, toOwnerSentence } from "../api.ts";
import { wallFormView } from "./wall.ts";

const SetupField = Schema.Literals(["Email", "Password", "Confirmation"]);

type SetupField = typeof SetupField.Type;

export const Problem = defineTaggedUnion({
  Invalid: { field: SetupField, sentence: Schema.String },
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
  RejectedSetupInput: { field: SetupField, sentence: Schema.String },
  FailedSetupOwner: { reason: Schema.String },
  CompletedFocus: {},
});

export type Message = typeof Message.Type;

export const OutMessage = defineMessageUnion({
  CreatedOwner: {},
  FoundOwner: {},
});

export type OutMessage = typeof OutMessage.Type;

export const init = (): Model => ({
  email: "",
  password: "",
  confirmation: "",
  isPasswordShown: false,
  isConfirmationShown: false,
  isCreating: false,
  maybeProblem: Option.none(),
});

const INPUT_FIELDS = new Map<PropertyKey, SetupField>([
  ["email", "Email"],
  ["password", "Password"],
]);

const rejectedFieldOf = (error: Action.InvalidInput) =>
  Array.findFirst(error.issues, ({ path, message }) =>
    Option.map(
      Option.flatMap(Array.head(path), (key) =>
        Option.fromNullishOr(INPUT_FIELDS.get(key))
      ),
      (field) => Message.RejectedSetupInput({ field, sentence: message })
    )
  );

export const SetupOwner = Command.define("SetupOwner", {
  args: { email: Schema.String, password: Schema.String },
  messages: [
    Message.SucceededSetupOwner,
    Message.RejectedSetupInput,
    Message.FailedSetupOwner,
  ],
  execute: ({ email, password }) =>
    issuer.setupOwner({ email, password }).pipe(
      Effect.as(Message.SucceededSetupOwner({ outcome: "Created" })),
      Effect.catchTags({
        OwnerExists: () =>
          Effect.succeed(
            Message.SucceededSetupOwner({ outcome: "AlreadyOwned" })
          ),
        InvalidInput: (error) =>
          Effect.fromOption(rejectedFieldOf(error), () => error),
      }),
      toOwnerSentence,
      Effect.match({
        onFailure: (reason) => Message.FailedSetupOwner({ reason }),
        onSuccess: (message) => message,
      })
    ),
});

const FORM_ID = "setup";

const FIELD_IDS: Readonly<Record<SetupField, string>> = {
  Email: "setup-email",
  Password: "setup-password",
  Confirmation: "setup-confirmation",
};

const invalid = (model: Model, field: SetupField, sentence: string) => ({
  model: modifyFields(model, {
    isCreating: () => false,
    maybeProblem: () => Option.some(Problem.Invalid({ field, sentence })),
  }),
  commands: [Focus.Focus({ id: FIELD_IDS[field] })],
});

const submitted = (model: Model): Update.Return<Model, Message> =>
  model.password === model.confirmation
    ? {
        model: modifyFields(model, {
          isCreating: () => true,
          isPasswordShown: () => false,
          isConfirmationShown: () => false,
          maybeProblem: () => Option.none(),
        }),
        commands: [
          Focus.Focus({ id: Card.submitId(FORM_ID) }),
          SetupOwner({ email: model.email.trim(), password: model.password }),
        ],
      }
    : invalid(model, "Confirmation", "Passwords do not match.");

export const update = (model: Model, message: Message) =>
  Message.match<Update.ReturnWithOutMessage<Model, Message, OutMessage>>(
    message,
    {
      UpdatedEmail: ({ value }) => ({
        model: modifyFields(model, { email: () => value }),
      }),
      UpdatedPassword: ({ value }) => ({
        model: modifyFields(model, { password: () => value }),
      }),
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
          Match.exhaustive
        ),
      }),
      RejectedSetupInput: ({ field, sentence }) =>
        invalid(model, field, sentence),
      FailedSetupOwner: ({ reason }) => ({
        model: modifyFields(model, {
          isCreating: () => false,
          maybeProblem: () => Option.some(Problem.Refused({ reason })),
        }),
      }),
      CompletedFocus: () => ({ model }),
    }
  );

const refusalView = (model: Model, h: HtmlBuilder<Message>): readonly Html[] =>
  Option.match(model.maybeProblem, {
    onNone: () => [],
    onSome: (problem) =>
      Problem.matchOrElse(
        problem,
        {
          Refused: ({ reason }) => [
            Notice.view(
              { tone: "Error", title: "Not created", body: [reason] },
              h
            ),
          ],
        },
        () => []
      ),
  });

const invalidSentenceOf = (
  model: Model,
  field: SetupField
): string | undefined =>
  Option.getOrUndefined(
    Option.flatMap(model.maybeProblem, (problem) =>
      Problem.matchOrElse(
        problem,
        {
          Invalid: ({ field: invalidField, sentence }) =>
            invalidField === field ? Option.some(sentence) : Option.none(),
        },
        () => Option.none()
      )
    )
  );

export const view = defineView<Model, Message>((model, h): Html =>
  wallFormView(
    "Set up clankerauth",
    {
      id: FORM_ID,
      title: "Setup",
      meta: "first run",
      submit: "create account",
      isBusy: model.isCreating,
      onSubmit: Message.SubmittedSetup(),
      body: [
        h.p(
          [h.Class("note-line")],
          [
            "Create the owner account for your private applications. It manages Clients and Resources and approves access, and it stays on your infrastructure.",
          ]
        ),
        ...refusalView(model, h),
        Field.view(
          {
            id: FIELD_IDS.Email,
            label: "Email",
            type: "email",
            value: model.email,
            onInput: (value) => Message.UpdatedEmail({ value }),
            isBoxed: true,
            isRequired: true,
            error: invalidSentenceOf(model, "Email"),
            inputAttributes: [
              h.Autocomplete("username"),
              h.Placeholder("owner@example.internal"),
            ],
          },
          h
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
            error: invalidSentenceOf(model, "Password"),
            help: `${passwordRule}. Save your password somewhere safe.`,
            autocomplete: "new-password",
          },
          h
        ),
        PasswordField.view(
          {
            id: FIELD_IDS.Confirmation,
            label: "Confirm password",
            value: model.confirmation,
            onInput: (value) => Message.UpdatedConfirmation({ value }),
            isShown: model.isConfirmationShown,
            onToggleShown: Message.ToggledConfirmationShown(),
            toggleLabel: "Show confirmation",
            isRequired: true,
            error: invalidSentenceOf(model, "Confirmation"),
            autocomplete: "new-password",
          },
          h
        ),
      ],
    },
    h
  )
);
