import { Option } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { documentPaths } from "./document-paths.ts";
import {
  clientsRouter,
  keysRouter,
  loginRouter,
  resourcesRouter,
  setupRouter,
  urlToAppRoute,
} from "./route.ts";

const url = (pathname: string) => ({
  protocol: "https:",
  host: "issuer.example",
  port: Option.none(),
  pathname,
  search: Option.none(),
  hash: Option.none(),
});

describe("document paths", () => {
  it("are the paths the routers build, each routed to a page", () => {
    const built = [
      clientsRouter(),
      resourcesRouter(),
      keysRouter(),
      loginRouter(),
      setupRouter(),
    ];

    expect(built.every((path) => documentPaths.includes(path))).toBe(true);
    expect(
      documentPaths.map((path) => urlToAppRoute(url(path))._tag)
    ).toStrictEqual([
      "Clients",
      "Resources",
      "Keys",
      "Login",
      "Setup",
      "Consent",
    ]);
  });
});
