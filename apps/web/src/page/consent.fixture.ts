import { Option } from "effect";

import { Model } from "./consent.ts";

export const CLIENT_ID = "https://client.fixture.invalid/metadata.json";

export const request = {
  clientId: CLIENT_ID,
  scopes: ["offline_access", "fixture:read"],
  resources: [],
  maybeRedirect: Option.none(),
  maybeClaims: Option.none(),
};

/** The provider signed the request and the asking client's name has come back. */
export const asking = Model.Asking({
  request,
  maybeName: Option.some("Fixture client"),
  granted: request.scopes,
  decision: "Undecided",
  maybeRefusal: Option.none(),
  isClaimsOpen: false,
});
