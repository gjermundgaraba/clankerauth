import { Option } from "effect";
import type { Url } from "foldkit/url";

export const urlAt = (pathname: string, search = "", hash = ""): Url => ({
  protocol: "https:",
  host: "issuer.fixture.invalid",
  port: Option.none(),
  pathname,
  search: search === "" ? Option.none() : Option.some(search),
  hash: hash === "" ? Option.none() : Option.some(hash),
});
