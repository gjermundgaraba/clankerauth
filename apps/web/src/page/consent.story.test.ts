import { Array, Option } from "effect";
import { Command, given, message, model, story } from "foldkit/story";
import { modifyFields } from "foldkit/struct";
import { describe, expect, test } from "vite-plus/test";

import { CLIENT_ID, asking } from "./consent.fixture.ts";
import { DecideConsent, FetchClientName, Message, Model, init, update } from "./consent.ts";

const signedQuery = new URLSearchParams({
  client_id: CLIENT_ID,
  scope: "offline_access fixture:read",
  sig: "fixture",
}).toString();

const askingWith =
  <A>(read: (state: typeof Model.Asking.Type) => A) =>
  (next: Model) =>
    Model.matchOrElse(next, { Asking: (state) => Option.some(read(state)) }, () => Option.none());

describe("consent update", () => {
  test("an unsigned request stops without asking the provider anything", () => {
    const init_ = init(new URLSearchParams({ client_id: CLIENT_ID }).toString());

    expect(Model.guards.Stopped(init_.model)).toBe(true);
    expect(init_.commands).toBeUndefined();
  });

  test("a signed request asks once the client's name arrives", () => {
    story(
      update,
      given(init(signedQuery).model),
      model((next) => {
        expect(Model.guards.Loading(next)).toBe(true);
      }),
      message(Message.SucceededFetchClientName({ maybeName: Option.some("Fixture client") })),
      model((next) => {
        expect(next).toEqual(asking);
      }),
    );
  });

  test("the request reads the client's name first", () => {
    const init_ = init(signedQuery);

    expect(Array.map(init_.commands ?? [], ({ name, args }) => ({ name, args }))).toEqual([
      { name: FetchClientName.name, args: { clientId: CLIENT_ID } },
    ]);
  });

  test("a client that cannot be named stops the page with the reason", () => {
    story(
      update,
      given(init(signedQuery).model),
      message(Message.FailedFetchClientName({ reason: "Fixture request failed" })),
      model((next) => {
        expect(next).toEqual(Model.Stopped({ reason: "Fixture request failed" }));
      }),
    );
  });

  test("unticking every permission is refused before anything is sent", () => {
    story(
      update,
      given(asking),
      message(Message.ToggledScope({ scope: "offline_access", isChecked: false })),
      message(Message.ToggledScope({ scope: "fixture:read", isChecked: false })),
      message(Message.ClickedAllow()),
      Command.expectNone(),
      model((next) => {
        expect(askingWith(({ decision }) => decision)(next)).toEqual(Option.some("Undecided"));
        expect(askingWith(({ maybeRefusal }) => maybeRefusal)(next)).toEqual(
          Option.some(Option.some("Tick at least one permission, or deny the request.")),
        );
      }),
    );
  });

  test("a narrowed approval names only what stays ticked", () => {
    story(
      update,
      given(asking),
      message(Message.ToggledScope({ scope: "offline_access", isChecked: false })),
      message(Message.ClickedAllow()),
      Command.expectExact(DecideConsent({ accept: true, maybeScope: Option.some("fixture:read") })),
      model((next) => {
        expect(askingWith(({ decision }) => decision)(next)).toEqual(Option.some("Allowing"));
      }),
      Command.resolve(DecideConsent, Message.SucceededDecideConsent()),
    );
  });

  test("a decision is made once", () => {
    story(
      update,
      given(modifyFields(asking, { decision: () => "Allowing" })),
      message(Message.ClickedAllow()),
      message(Message.ClickedDeny()),
      Command.expectNone(),
    );
  });

  test("an untouched approval names every scope asked for", () => {
    story(
      update,
      given(asking),
      message(Message.ClickedAllow()),
      Command.resolve(
        DecideConsent({ accept: true, maybeScope: Option.some("offline_access fixture:read") }),
        Message.SucceededDecideConsent(),
      ),
    );
  });

  test("a refused decision can be made again, with the reason shown", () => {
    story(
      update,
      given(asking),
      message(Message.ClickedDeny()),
      Command.resolve(
        DecideConsent({ accept: false, maybeScope: Option.none() }),
        Message.FailedDecideConsent({ reason: "Restart from your application." }),
      ),
      model((next) => {
        expect(askingWith(({ decision }) => decision)(next)).toEqual(Option.some("Undecided"));
        expect(askingWith(({ maybeRefusal }) => maybeRefusal)(next)).toEqual(
          Option.some(Option.some("Restart from your application.")),
        );
      }),
    );
  });
});
