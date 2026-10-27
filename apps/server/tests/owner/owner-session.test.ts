import { it } from "@effect/vitest";
import { Effect, Schema } from "effect";
import { expect } from "vite-plus/test";

import { OwnerAccount } from "../../src/owner/owner.ts";
import { decodeJson } from "../mcp-oauth-helper.ts";
import { testWebApplication, WebApplication } from "../test-issuer.ts";

const owner = {
  email: "owner@example.internal",
  password: "test-only password123",
};

const OpenApi = Schema.Struct({
  components: Schema.Struct({
    securitySchemes: Schema.Record(Schema.String, Schema.Unknown),
  }),
});

const signIn = (origin: string) =>
  Effect.gen(function* () {
    const app = yield* WebApplication;
    yield* (yield* OwnerAccount).create(owner);

    const post = (
      path: string,
      body: Readonly<Record<string, string>>,
      cookie?: string
    ) => {
      const headers = new Headers({
        origin,
        "content-type": "application/json",
      });

      if (cookie !== undefined) {
        headers.set("cookie", cookie);
      }

      return Effect.promise(
        async () =>
          await app(
            new Request(`${origin}${path}`, {
              method: "POST",
              headers,
              body: JSON.stringify(body),
            })
          )
      );
    };

    const login = yield* post("/api/auth/sign-in/email", owner);
    expect(
      login.status,
      yield* Effect.promise(async () => await login.clone().text())
    ).toBe(200);

    const set = login.headers
      .getSetCookie()
      .find((cookie) => cookie.includes("session_token="));

    expect(set).toBeDefined();
    const [pair = ""] = set!.split(";");

    return {
      set: set!,
      value: pair.slice(pair.indexOf("=") + 1),
      listClients: (cookie: string) => post("/api/listClients", {}, cookie),
      openapi: Effect.promise(
        async () => await app(new Request(`${origin}/openapi.json`))
      ),
    };
  });

it.live.each([
  {
    scheme: "HTTPS",
    origin: "https://clankerauth.home.example",
    name: "__Secure-better-auth.session_token",
    secure: true,
  },
  {
    scheme: "HTTP",
    origin: "http://localhost:3000",
    name: "better-auth.session_token",
    secure: false,
  },
] as const)(
  "over $scheme, owner actions authenticate with the session cookie $name, as OpenAPI declares",
  ({ origin, name, secure }) =>
    Effect.gen(function* () {
      const session = yield* signIn(origin);

      expect(/;\s*Secure(?:;|$)/iu.test(session.set)).toBe(secure);

      const listed = yield* session.listClients(`${name}=${session.value}`);
      expect(
        listed.status,
        yield* Effect.promise(async () => await listed.clone().text())
      ).toBe(200);
      expect(yield* decodeJson(Schema.Json)(listed)).toHaveProperty(
        "email",
        owner.email
      );

      const document = yield* decodeJson(OpenApi)(yield* session.openapi);
      expect(Object.values(document.components.securitySchemes)).toContainEqual(
        expect.objectContaining({ type: "apiKey", in: "cookie", name })
      );
    }).pipe(Effect.provide(testWebApplication({ baseURL: origin })))
);
