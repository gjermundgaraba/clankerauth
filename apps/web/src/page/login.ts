import { Boolean, Effect, Option, Schema } from "effect";
import { Command } from "foldkit";
import type { Html, HtmlBuilder } from "foldkit/html";
import { defineMessageUnion } from "foldkit/message";
import { load } from "foldkit/navigation";
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

import { signIn } from "../api.ts";
import { clientsRouter } from "../route.ts";
import { wallCardView } from "./wall.ts";

// MODEL

const LoginField = Schema.Literals(["Email", "Password"]);

type LoginField = typeof LoginField.Type;

export const Problem = defineTaggedUnion({
  Missing: { field: LoginField },
  Refused: { reason: Schema.String },
});

type Problem = typeof Problem.Type;

/** Where a sign-in goes on to: back into an OAuth authorization, which the provider client
 *  continues itself, or to a page of this origin. */
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

/**
 * A sign-in for the address's query. `rd` is where to go once signed in (forward auth names
 * the protected page), and `fallback` where to go without one; `sig` marks a sign-in inside
 * an OAuth authorization, which the provider client continues itself.
 */
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
      : Continuation.RedirectTo({ destination: query.get("rd") ?? fallback }),
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

// Forward auth continues on this origin, which validates the real destination; anywhere else
// is not this issuer's to send the owner to.
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

/**
 * The navigation that follows a sign-in, which an owner already signed in takes at once.
 * Inside an authorization there is none: only signing in through the form continues it.
 */
export const continuationOf = (model: Model) =>
  Continuation.match(model.continuation, {
    ContinueAuthorization: () => Option.none(),
    RedirectTo: ({ destination }) => Option.some(ContinueAfterSignIn({ destination })),
  });

// UPDATE

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
      commands: [SignIn({ email: model.email.trim(), password: model.password })],
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
    // NOTE: inside an authorization the provider client has already followed the redirect,
    // and a second navigation would cancel it, so the button stays busy until the page goes.
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
  wallCardView(
    "Sign in to clankerauth",
    {
      title: "Sign in",
      meta: "owner",
      onSubmit: Message.SubmittedSignIn(),
      actions: [
        Button.view(
          {
            label: "sign in",
            type: "submit",
            variant: "Primary",
            isDefault: true,
            isBusy: model.isSigningIn,
          },
          h,
        ),
      ],
      body: [
        h.p(
          [h.Class("note-line")],
          [
            "Use your local account to continue. Password sign-in only: there is no external identity provider.",
          ],
        ),
        ...refusalView(model, h),
        Fields.view(
          {
            isBusy: model.isSigningIn,
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
                  error: missingSentenceOf(model, "Email"),
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
                  error: missingSentenceOf(model, "Password"),
                  autocomplete: "current-password",
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
