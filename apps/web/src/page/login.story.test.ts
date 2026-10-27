import { Card, Focus } from "@gjermundgaraba-designs/pixel-paper";
import { Option } from "effect";
import { Command, given, message, model, story } from "foldkit/story";
import { describe, expect, it } from "vite-plus/test";

import {
  ContinueAfterSignIn,
  Message,
  Problem,
  SignIn,
  init,
  update,
} from "./login.ts";

const filledIn = (search: string) => [
  given(init(search, "/")),
  message(Message.UpdatedEmail({ value: " owner@fixture.invalid " })),
  message(Message.UpdatedPassword({ value: "correct horse" })),
];

describe("login update", () => {
  it("a missing field is named and focused, and nothing is sent", () => {
    story(
      update,
      given(init("", "/")),
      message(Message.SubmittedSignIn()),
      Command.resolve(
        Focus.Focus({ id: "login-email" }),
        Message.CompletedFocus()
      ),
      model((next) => {
        expect(next.maybeProblem).toStrictEqual(
          Option.some(Problem.Missing({ field: "Email" }))
        );
        expect(next.isSigningIn).toBe(false);
      })
    );
  });

  it("a sign-in goes on to the page that asked for it", () => {
    story(
      update,
      ...filledIn("rd=%2Fkeys"),
      message(Message.SubmittedSignIn()),
      Command.expectExact(
        Focus.Focus({ id: Card.submitId("login") }),
        SignIn({ email: "owner@fixture.invalid", password: "correct horse" })
      ),
      model((next) => {
        expect(next.isSigningIn).toBe(true);
      }),
      Command.resolve(Focus.Focus, Message.CompletedFocus()),
      Command.resolve(SignIn, Message.SucceededSignIn()),
      Command.resolve(
        ContinueAfterSignIn({ destination: "/keys" }),
        Message.CompletedContinueAfterSignIn()
      )
    );
  });

  it("a sign-in inside an authorization leaves the navigation to the provider client", () => {
    story(
      update,
      ...filledIn("sig=fixture"),
      message(Message.SubmittedSignIn()),
      Command.resolve(
        Focus.Focus({ id: Card.submitId("login") }),
        Message.CompletedFocus()
      ),
      Command.resolve(SignIn, Message.SucceededSignIn()),
      Command.expectNone(),
      model((next) => {
        expect(next.isSigningIn).toBe(true);
      })
    );
  });

  it("a refused sign-in says why and can be sent again", () => {
    story(
      update,
      ...filledIn(""),
      message(Message.SubmittedSignIn()),
      Command.resolve(
        Focus.Focus({ id: Card.submitId("login") }),
        Message.CompletedFocus()
      ),
      Command.resolve(
        SignIn,
        Message.FailedSignIn({ reason: "Sign-in failed." })
      ),
      model((next) => {
        expect(next.isSigningIn).toBe(false);
        expect(next.maybeProblem).toStrictEqual(
          Option.some(Problem.Refused({ reason: "Sign-in failed." }))
        );
      }),
      message(Message.SubmittedSignIn()),
      Command.resolve(
        Focus.Focus({ id: Card.submitId("login") }),
        Message.CompletedFocus()
      ),
      Command.resolve(
        SignIn({ email: "owner@fixture.invalid", password: "correct horse" }),
        Message.SucceededSignIn()
      ),
      Command.resolve(
        ContinueAfterSignIn({ destination: "/" }),
        Message.CompletedContinueAfterSignIn()
      )
    );
  });
});
