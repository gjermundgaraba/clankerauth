import { Option } from "effect";
import { Command, click, expect, given, role, scene, selector, text } from "foldkit/scene";
import { describe, test } from "vite-plus/test";

import { asking } from "./consent.fixture.ts";
import { DecideConsent, Message, Model, update, view } from "./consent.ts";

describe("consent view", () => {
  test("the page names the client and every permission it asks for, on a full-width card", () => {
    scene(
      { update, view },
      given(asking),
      expect(selector(".card.narrow")).toBeAbsent(),
      expect(text("Fixture client", { exact: false })).toExist(),
      expect(role("checkbox", { name: "offline_access" })).toBeChecked(),
      expect(role("checkbox", { name: "fixture:read" })).toBeChecked(),
      expect(role("button", { name: "allow access" })).toExist(),
      expect(role("button", { name: "deny" })).toExist(),
    );
  });

  test("an approval sends only the permissions left ticked", () => {
    scene(
      { update, view },
      given(asking),
      click(role("checkbox", { name: "offline_access" })),
      expect(role("checkbox", { name: "offline_access" })).not.toBeChecked(),
      click(role("button", { name: "allow access" })),
      Command.resolve(
        DecideConsent({ accept: true, maybeScope: Option.some("fixture:read") }),
        Message.SucceededDecideConsent(),
      ),
    );
  });

  test("a refused decision is shown on the page", () => {
    scene(
      { update, view },
      given(asking),
      click(role("button", { name: "deny" })),
      Command.resolve(
        DecideConsent,
        Message.FailedDecideConsent({ reason: "Restart from your application." }),
      ),
      expect(text("Restart from your application.")).toExist(),
      expect(role("button", { name: "deny" })).toExist(),
    );
  });

  test("a request that cannot be answered says why", () => {
    scene(
      { update, view },
      given(Model.Stopped({ reason: "The request was not signed." })),
      expect(selector(".card.narrow")).toExist(),
      expect(text("Unable to continue")).toExist(),
      expect(text("The request was not signed.")).toExist(),
      expect(role("button", { name: "allow access" })).toBeAbsent(),
    );
  });
});
