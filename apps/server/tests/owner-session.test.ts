/**
 * The dashboard's owner session: the provider's own session cookie, named as it names it for
 * the deployment, `__Secure-` prefixed over HTTPS, and the cookie owner actions authenticate
 * with, end to end from sign-in.
 */
import { afterEach, expect, test } from "vite-plus/test";
import { createOwner } from "../src/auth.ts";
import { openIssuer, type Issuer } from "./issuer.ts";
import { webApplication } from "./web-application.ts";

const owner = { email: "owner@example.internal", password: "test-only password123" };

let issuer: Issuer | undefined;

let handle: ReturnType<typeof webApplication> | undefined;

afterEach(async () => {
  await handle?.dispose();
  await issuer?.close();
  handle = undefined;
  issuer = undefined;
});

/** Opens an issuer at `origin`, signs the owner in, and reads the session cookie it set. */
const signIn = async (origin: string) => {
  issuer = await openIssuer({ baseURL: origin });
  const app = webApplication(issuer.service);
  handle = app;
  await issuer.run(createOwner(issuer.service, owner));

  const post = (path: string, body: Readonly<Record<string, string>>, cookie?: string) => {
    const headers = new Headers({ origin, "content-type": "application/json" });

    if (cookie !== undefined) headers.set("cookie", cookie);

    return app(
      new Request(`${origin}${path}`, { method: "POST", headers, body: JSON.stringify(body) }),
    );
  };

  const login = await post("/api/auth/sign-in/email", owner);
  expect(login.status, await login.clone().text()).toBe(200);

  const [set] = login.headers.getSetCookie().filter((cookie) => cookie.includes("session_token="));

  expect(set).toBeDefined();
  const [pair = ""] = set!.split(";");

  return {
    /** The `Set-Cookie` header the sign-in answered with. */
    set: set!,
    value: pair.slice(pair.indexOf("=") + 1),
    /** An owner action, called with `cookie` alone. */
    listClients: (cookie: string) => post("/api/listClients", {}, cookie),
    openapi: () => app(new Request(`${origin}/openapi.json`)),
  };
};

test.for([
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
  async ({ origin, name, secure }) => {
    const session = await signIn(origin);

    // The session cookie is sent over HTTPS only when the deployment is served over HTTPS.
    expect(/;\s*Secure(;|$)/i.test(session.set)).toBe(secure);

    // The provider's own name for the deployment, `__Secure-` prefixed over HTTPS.
    const listed = await session.listClients(`${name}=${session.value}`);
    expect(listed.status, await listed.clone().text()).toBe(200);
    expect((await listed.json()).email).toBe(owner.email);

    // The server's binding names the cookie it reads, in its OpenAPI document too.
    const document = await (await session.openapi()).json();
    expect(Object.values(document.components.securitySchemes)).toContainEqual(
      expect.objectContaining({ type: "apiKey", in: "cookie", name }),
    );
  },
);
