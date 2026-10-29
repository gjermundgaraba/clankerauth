import { Card, Focus } from "@gjermundgaraba/pixel-paper";
import { Option } from "effect";
import {
  Command,
  expectOutMessage,
  given,
  message,
  model,
  story,
} from "foldkit/story";
import { describe, expect, it } from "vite-plus/test";

import {
  Message,
  OutMessage,
  Problem,
  SetupOwner,
  init,
  update,
} from "./setup.ts";

const filledIn = [
  given(init()),
  message(Message.UpdatedEmail({ value: "owner@fixture.invalid" })),
  message(Message.UpdatedPassword({ value: "correct horse battery" })),
  message(Message.UpdatedConfirmation({ value: "correct horse battery" })),
];

describe("setup update", () => {
  it("a password that does not match its confirmation is named and focused", () => {
    story(
      update,
      ...filledIn,
      message(Message.UpdatedConfirmation({ value: "something else" })),
      message(Message.SubmittedSetup()),
      Command.resolve(
        Focus.Focus({ id: "setup-confirmation" }),
        Message.CompletedFocus()
      ),
      model((next) => {
        expect(next.isCreating).toBe(false);
        expect(next.maybeProblem).toStrictEqual(
          Option.some(
            Problem.Invalid({
              field: "Confirmation",
              sentence: "Passwords do not match.",
            })
          )
        );
      })
    );
  });

  it("a field the issuer rejects is named with the issuer's sentence and focused", () => {
    story(
      update,
      ...filledIn,
      message(Message.SubmittedSetup()),
      Command.resolve(
        Focus.Focus({ id: Card.submitId("setup") }),
        Message.CompletedFocus()
      ),
      Command.resolve(
        SetupOwner,
        Message.RejectedSetupInput({
          field: "Password",
          sentence: "Passwords have 8 to 128 characters",
        })
      ),
      Command.resolve(
        Focus.Focus({ id: "setup-password" }),
        Message.CompletedFocus()
      ),
      model((next) => {
        expect(next.isCreating).toBe(false);
        expect(next.maybeProblem).toStrictEqual(
          Option.some(
            Problem.Invalid({
              field: "Password",
              sentence: "Passwords have 8 to 128 characters",
            })
          )
        );
      })
    );
  });

  it("a created owner is reported to the application", () => {
    story(
      update,
      ...filledIn,
      message(Message.SubmittedSetup()),
      Command.expectExact(
        Focus.Focus({ id: Card.submitId("setup") }),
        SetupOwner({
          email: "owner@fixture.invalid",
          password: "correct horse battery",
        })
      ),
      model((next) => {
        expect(next.isCreating).toBe(true);
      }),
      Command.resolve(Focus.Focus, Message.CompletedFocus()),
      Command.resolve(
        SetupOwner,
        Message.SucceededSetupOwner({ outcome: "Created" })
      ),
      expectOutMessage(OutMessage.CreatedOwner())
    );
  });

  it("an issuer someone else set up first sends the owner to sign in", () => {
    story(
      update,
      ...filledIn,
      message(Message.SubmittedSetup()),
      Command.resolve(
        Focus.Focus({ id: Card.submitId("setup") }),
        Message.CompletedFocus()
      ),
      Command.resolve(
        SetupOwner,
        Message.SucceededSetupOwner({ outcome: "AlreadyOwned" })
      ),
      expectOutMessage(OutMessage.FoundOwner())
    );
  });

  it("a refused setup says why and can be sent again", () => {
    story(
      update,
      ...filledIn,
      message(Message.SubmittedSetup()),
      Command.resolve(
        Focus.Focus({ id: Card.submitId("setup") }),
        Message.CompletedFocus()
      ),
      Command.resolve(
        SetupOwner,
        Message.FailedSetupOwner({ reason: "Fixture request failed" })
      ),
      model((next) => {
        expect(next.isCreating).toBe(false);
        expect(next.maybeProblem).toStrictEqual(
          Option.some(Problem.Refused({ reason: "Fixture request failed" }))
        );
      })
    );
  });
});
