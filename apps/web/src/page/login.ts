import { returnToParameter } from "@gjermundgaraba/clankerauth-sdk/session";
import { Boolean, Effect, Option, Schema } from "effect";
import { Command } from "foldkit";
import type { Html, HtmlBuilder } from "foldkit/html";
import { defineMessageUnion } from "foldkit/message";
import { load } from "foldkit/navigation";
import { defineTaggedUnion } from "foldkit/schema";
import { modifyFields } from "foldkit/struct";
import { defineView } from "foldkit/submodel";
import type * as Update from "foldkit/update";
import { Card, Field, Focus, Notice, PasswordField } from "@gjermundgaraba-designs/pixel-paper";

import { signIn } from "../api.ts";
import { clientsRouter } from "../route.ts";
import { wallFormView } from "./wall.ts";

// MODEL

const LoginField = Schema.Literals(["Email", "Password"]);

type LoginField = typeof LoginField.Type;

export const Problem = defineTaggedUnion({
  Missing: { field: LoginField },
  Refused: { reason: Schema.String },
});

type Problem = typeof Problem.Type;

export const Continuation = defineTaggedUnion({
  ContinueAuthorization: {},
  RedirectTo: { destination: Schema.String },
});

export const Model = Schema.Struct({
  email: Schema.String,
  password: Schema.String,
  isPasswordShown: Schema.Boolean,
  isSigningIn: Schema.Boolean,
  maybeProblem: Schema.Option(Problem),
  continuation: Continuation,
});

export type Model = typeof Model.Type;

type UpdateReturn = Update.Return<Model, Message>;

// MESSAGE

export const Message = defineMessageUnion({
  UpdatedEmail: { value: Schema.String },
  UpdatedPassword: { value: Schema.String },
  ToggledPasswordShown: {},
  SubmittedSignIn: {},
  SucceededSignIn: {},
  FailedSignIn: { reason: Schema.String },
  CompletedFocus: {},
  CompletedContinueAfterSignIn: {},
});

export type Message = typeof Message.Type;

// INIT

export const init = (search: string, fallback: string): Model => {
  const query = new URLSearchParams(search);

  return {
    email: "",
    password: "",
    isPasswordShown: false,
    isSigningIn: false,
    maybeProblem: Option.none(),
    continuation: query.has("sig")
      ? Continuation.ContinueAuthorization()
      : Continuation.RedirectTo({ destination: query.get(returnToParameter) ?? fallback }),
  };
};

// COMMAND

export const SignIn = Command.define("SignIn", {
  args: { email: Schema.String, password: Schema.String },
  messages: [Message.SucceededSignIn, Message.FailedSignIn],
  execute: ({ email, password }) =>
    signIn(email, password).pipe(
      Effect.match({
        onFailure: (reason) => Message.FailedSignIn({ reason }),
        onSuccess: () => Message.SucceededSignIn(),
      }),
    ),
});

// why: never redirect off this origin; forward auth continues here and validates the destination
export const ContinueAfterSignIn = Command.define("ContinueAfterSignIn", {
  args: { destination: Schema.String },
  messages: [Message.CompletedContinueAfterSignIn],
  execute: ({ destination }) =>
    Effect.suspend(() =>
      load(
        URL.canParse(destination, location.origin) &&
          new URL(destination, location.origin).origin === location.origin
          ? destination
          : clientsRouter(),
      ),
    ).pipe(Effect.as(Message.CompletedContinueAfterSignIn())),
});

export const continuationOf = (model: Model) =>
  Continuation.match(model.continuation, {
    ContinueAuthorization: () => Option.none(),
    RedirectTo: ({ destination }) => Option.some(ContinueAfterSignIn({ destination })),
  });

// UPDATE

const FORM_ID = "login";

const FIELD_IDS: Readonly<Record<LoginField, string>> = {
  Email: "login-email",
  Password: "login-password",
};

const missingFieldOf = (model: Model): Option.Option<LoginField> => {
  if (model.email.trim() === "") {
    return Option.some("Email");
  }

  if (model.password === "") {
    return Option.some("Password");
  }

  return Option.none();
};

const submitted = (model: Model): UpdateReturn =>
  Option.match(missingFieldOf(model), {
    onNone: () => ({
      model: modifyFields(model, {
        isSigningIn: () => true,
        isPasswordShown: () => false,
        maybeProblem: () => Option.none(),
      }),
      commands: [
        Focus.Focus({ id: Card.submitId(FORM_ID) }),
        SignIn({ email: model.email.trim(), password: model.password }),
      ],
    }),
    onSome: (field) => ({
      model: modifyFields(model, { maybeProblem: () => Option.some(Problem.Missing({ field })) }),
      commands: [Focus.Focus({ id: FIELD_IDS[field] })],
    }),
  });

export const update = (model: Model, message: Message) =>
  Message.match<UpdateReturn>(message, {
    UpdatedEmail: ({ value }) => ({ model: modifyFields(model, { email: () => value }) }),
    UpdatedPassword: ({ value }) => ({ model: modifyFields(model, { password: () => value }) }),
    ToggledPasswordShown: () => ({
      model: modifyFields(model, { isPasswordShown: Boolean.not }),
    }),
    SubmittedSignIn: () => (model.isSigningIn ? { model } : submitted(model)),
    SucceededSignIn: () =>
      Option.match(continuationOf(model), {
        onNone: () => ({ model }),
        onSome: (command) => ({ model, commands: [command] }),
      }),
    FailedSignIn: ({ reason }) => ({
      model: modifyFields(model, {
        isSigningIn: () => false,
        maybeProblem: () => Option.some(Problem.Refused({ reason })),
      }),
    }),
    CompletedFocus: () => ({ model }),
    CompletedContinueAfterSignIn: () => ({ model }),
  });

// VIEW

const MISSING_SENTENCES: Readonly<Record<LoginField, string>> = {
  Email: "Enter your email address.",
  Password: "Enter your password.",
};

const refusalView = (model: Model, h: HtmlBuilder<Message>): ReadonlyArray<Html> =>
  Option.match(model.maybeProblem, {
    onNone: () => [],
    onSome: (problem) =>
      Problem.matchOrElse(
        problem,
        {
          Refused: ({ reason }) => [
            Notice.view({ tone: "Error", title: "Not signed in", body: [reason] }, h),
          ],
        },
        () => [],
      ),
  });

const missingSentenceOf = (model: Model, field: LoginField): string | undefined =>
  Option.exists(model.maybeProblem, (problem) =>
    Problem.matchOrElse(problem, { Missing: (missing) => missing.field === field }, () => false),
  )
    ? MISSING_SENTENCES[field]
    : undefined;

export const view = defineView<Model, Message>((model, h): Html =>
  wallFormView(
    "Sign in to clankerauth",
    {
      id: FORM_ID,
      title: "Sign in",
      meta: "owner",
      submit: "sign in",
      isBusy: model.isSigningIn,
      onSubmit: Message.SubmittedSignIn(),
      body: [
        h.p(
          [h.Class("note-line")],
          [
            "Use your local account to continue. Password sign-in only: there is no external identity provider.",
          ],
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
            error: missingSentenceOf(model, "Email"),
            inputAttributes: [h.Autocomplete("username"), h.Placeholder("owner@example.internal")],
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
            error: missingSentenceOf(model, "Password"),
            autocomplete: "current-password",
          },
          h,
        ),
      ],
    },
    h,
  ),
);
