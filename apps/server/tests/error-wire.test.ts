import { expect, test } from "vite-plus/test";
import { Schema } from "effect";
import { BadRequest, InternalServerError } from "@clankerauth/admin-api";

test("encoded error expectations preserve exact wire assertions", async () => {
  const expected = Schema.encodeSync(InternalServerError)(
    new InternalServerError({ error: "Request could not be completed" }),
  );

  expect(Object.keys(expected).sort()).toEqual(["_tag", "error"]);

  const response = Response.json({ ...expected, secret: "must not escape" });
  const actual = await response.json();

  // Decoding the actual response would erase the leak and weaken this assertion.
  expect(actual).not.toEqual(expected);
  expect(
    Schema.encodeSync(InternalServerError)(Schema.decodeUnknownSync(InternalServerError)(actual)),
  ).toEqual(expected);
});

test("BadRequest wire expectations contain only the public error contract", () => {
  const expected = Schema.encodeSync(BadRequest)(new BadRequest({ error: "Invalid request" }));

  expect(Object.keys(expected).sort()).toEqual(["_tag", "error"]);
  expect(expected.error).toBe("Invalid request");
});
