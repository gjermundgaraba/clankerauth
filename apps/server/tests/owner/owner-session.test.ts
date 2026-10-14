/**
 * The dashboard's owner session: the provider's own session cookie, named as it names it for
 * the deployment, `__Secure-` prefixed over HTTPS, and the cookie owner actions authenticate
 * with, end to end from sign-in.
 */
import { it } from "@effect/vitest";
import { Effect } from "effect";
import { expect } from "vite-plus/test";
import { testWebApplication, WebApplication } from "../test-issuer.ts";
import { OwnerAccount } from "../../src/owner/owner.ts";

const owner = { email: "owner@example.internal", password: "test-only password123" };

/** Signs the owner in to the issuer at `origin` and reads the session cookie it set. */
const signIn = (origin: string) =>
  Effect.gen(function* () {
    const app = yield* WebApplication;
    yield* (yield* OwnerAccount).create(owner);

    const post = (path: string, body: Readonly<Record<string, string>>, cookie?: string) => {
      const headers = new Headers({ origin, "content-type": "application/json" });

      if (cookie !== undefined) headers.set("cookie", cookie);

      return Effect.promise(() =>
        app(
          new Request(`${origin}${path}`, { method: "POST", headers, body: JSON.stringify(body) }),
        ),
      );
    };

    const login = yield* post("/api/auth/sign-in/email", owner);
    expect(login.status, yield* Effect.promise(() => login.clone().text())).toBe(200);

    const [set] = login.headers
      .getSetCookie()
      .filter((cookie) => cookie.includes("session_token="));

    expect(set).toBeDefined();
    const [pair = ""] = set!.split(";");

    return {
      /** The `Set-Cookie` header the sign-in answered with. */
      set: set!,
      value: pair.slice(pair.indexOf("=") + 1),
      /** An owner action, called with `cookie` alone. */
      listClients: (cookie: string) => post("/api/listClients", {}, cookie),
      openapi: Effect.promise(() => app(new Request(`${origin}/openapi.json`))),
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
  "over $scheme, owner actions authenticate with the session cookie $name",
  ({ origin, name, secure }) =>
    Effect.gen(function* () {
      const session = yield* signIn(origin);

      // The session cookie is sent over HTTPS only when the deployment is served over HTTPS.
      expect(/;\s*Secure(;|$)/i.test(session.set)).toBe(secure);

      // The provider's own name for the deployment, `__Secure-` prefixed over HTTPS.
      const listed = yield* session.listClients(`${name}=${session.value}`);
      expect(listed.status, yield* Effect.promise(() => listed.clone().text())).toBe(200);
      expect((yield* Effect.promise(() => listed.json())).email).toBe(owner.email);

      // The server's binding names the cookie it reads, in its OpenAPI document too.
      const openapi = yield* session.openapi;
      const document = yield* Effect.promise(() => openapi.json());
      expect(Object.values(document.components.securitySchemes)).toContainEqual(
        expect.objectContaining({ type: "apiKey", in: "cookie", name }),
      );
    }).pipe(Effect.provide(testWebApplication({ baseURL: origin }))),
);
