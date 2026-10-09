import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Schema } from "effect";
import { expect, onTestFinished, test } from "vite-plus/test";
import { startDisposableIssuer } from "@gjermundgaraba/clankerauth-dev";
import { Credentials, type SignIn } from "../src/credentials.ts";

const binary = fileURLToPath(new URL("../dist/main.mjs", import.meta.url));

const notes = { identifier: "http://notes.invalid/", name: "Notes", scopes: ["notes:read"] };

interface Run {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * An issuer of the test's own and its owner's dashboard session, which approves a sign-in
 * as the browser would. Each test has its own: the issuer limits token requests to twenty
 * a minute, which a shared one would reach.
 */
const startOwner = async () => {
  const issuer = await startDisposableIssuer({
    resources: [notes],
    client: { name: "Unused", redirect: "http://127.0.0.1/unused", resources: [] },
  });

  onTestFinished(() => issuer.close());

  const signedIn = await fetch(`${issuer.url}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { origin: issuer.url, "content-type": "application/json" },
    body: JSON.stringify({ email: issuer.owner.email, password: issuer.owner.password }),
  });

  expect(signedIn.status).toBe(200);

  const cookie = signedIn.headers
    .getSetCookie()
    .map((part) => part.split(";")[0])
    .join("; ");

  return { issuer, cookie, administration: `${issuer.url}/` };
};

type Owner = Awaited<ReturnType<typeof startOwner>>;

const Redirect = Schema.Struct({ url: Schema.String });

/** Approve an authorization URL as the signed-in owner's browser, through consent. */
const approve = async ({ issuer, cookie }: Owner, authorization: string) => {
  const authorize = await fetch(authorization, { headers: { cookie }, redirect: "manual" });

  // A script's request is answered with the redirect as JSON, a browser's with a 302.
  const location =
    authorize.status === 302
      ? (authorize.headers.get("location") ?? "")
      : Schema.decodeUnknownSync(Redirect)(await authorize.json()).url;

  const consentPage = new URL(location, issuer.url);

  expect(consentPage.pathname).toBe("/consent");

  const consent = await fetch(`${issuer.url}/api/auth/oauth2/consent`, {
    method: "POST",
    headers: { cookie, origin: issuer.url, "content-type": "application/json" },
    body: JSON.stringify({ accept: true, oauth_query: consentPage.search.slice(1) }),
  });

  expect(consent.status, await consent.clone().text()).toBe(200);

  const callback = await fetch(Schema.decodeUnknownSync(Redirect)(await consent.json()).url);
  expect(callback.status).toBe(200);
  // The page claims nothing: the sign-in is decided after the browser has it.
  expect(await callback.text()).toContain("Return to the terminal.");
};

/** The sign-in to `resource` among the kept ones; a test fails without it. */
const signInTo = (credentials: Credentials, resource: string): SignIn => {
  const found = credentials.signIns.find((held) => held.resource === resource);

  if (found === undefined) throw new Error(`No sign-in to ${resource}`);

  return found;
};

/** The audience a printed access token was issued for. */
const audience = (jwt: string) =>
  Schema.decodeUnknownSync(
    Schema.Struct({ aud: Schema.Union([Schema.String, Schema.Array(Schema.String)]) }),
  )(JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString())).aud;

/** A CLI with a config directory of its own, signed out. */
const home = async () => {
  const config = await mkdtemp(join(tmpdir(), "clankerauth-cli-"));

  onTestFinished(() => rm(config, { recursive: true, force: true }));

  const file = join(config, "clankerauth", "credentials.json");

  /**
   * Run the packed CLI. `onStderr` sees its stderr as it arrives, which is where `login`
   * prints the approval URL while it waits.
   */
  const run = (args: ReadonlyArray<string>, onStderr?: (text: string, stop: () => void) => void) =>
    new Promise<Run>((resolve, reject) => {
      const child = spawn(process.execPath, [binary, ...args], {
        env: { ...process.env, XDG_CONFIG_HOME: config },
      });

      let stdout = "";
      let stderr = "";

      child.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString();
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString();
        onStderr?.(stderr, () => child.kill());
      });
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout, stderr }));
    });

  /** Sign in at `owner`'s issuer with the packed CLI, approving the URL it prints. */
  const login = async (owner: Owner, ...flags: ReadonlyArray<string>) => {
    let approving: Promise<void> | undefined;

    const result = await run(["login", owner.issuer.url, ...flags], (stderr, stop) => {
      const url = /https?:\/\/\S+\/oauth2\/authorize\S+/.exec(stderr)?.[0];

      // A failed approval would leave the sign-in waiting for its whole window.
      if (url !== undefined && approving === undefined)
        approving = approve(owner, url).catch((error: Error) => {
          stop();
          throw error;
        });
    });

    await approving;

    return result;
  };

  const stored = async () =>
    Schema.decodeUnknownSync(Schema.fromJsonString(Credentials))(await readFile(file, "utf8"));

  /** Mark every kept access token expired, so the next command refreshes it. */
  const expireAll = async () => {
    const credentials = await stored();

    await writeFile(
      file,
      JSON.stringify({
        ...credentials,
        signIns: credentials.signIns.map((signIn) => ({
          ...signIn,
          expiresAt: new Date(0).toISOString(),
        })),
      }),
      { mode: 0o600 },
    );
  };

  return { file, run, login, stored, expireAll };
};

/** An issuer, and a CLI signed in to its administration. */
const signedIn = async (...flags: ReadonlyArray<string>) => {
  const owner = await startOwner();
  const cli = await home();
  const result = await cli.login(owner, ...flags);

  expect(result.code, result.stderr).toBe(0);

  return { owner, cli };
};

/** Refresh `refreshToken` at the token endpoint directly, as a revoked one is refused. */
const refreshDirectly = (
  { issuer }: Owner,
  clientId: string,
  refreshToken: string,
  resource: string,
) =>
  fetch(`${issuer.issuer}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: clientId,
      refresh_token: refreshToken,
      resource,
    }),
  });

const Created = Schema.Struct({ keyId: Schema.String, key: Schema.String });

const Listed = Schema.Struct({ keys: Schema.Array(Schema.Struct({ keyId: Schema.String })) });

test("an administration command before signing in says how to sign in", async () => {
  const result = await (await home()).run(["list-api-keys"]);

  expect(result.code).toBe(1);
  expect(result.stderr).toContain("Not signed in: run `clankerauth login <url>` first.");
  expect(result.stdout).toBe("");
});

test("login signs in through the owner's approval and keeps the sign-in to its owner", async () => {
  const owner = await startOwner();
  const cli = await home();
  const result = await cli.login(owner);

  expect(result.code, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    url: owner.issuer.url,
    resource: owner.administration,
    scope: "clankerauth:read clankerauth:write offline_access",
  });

  const credentials = await cli.stored();
  expect(credentials.url).toBe(owner.issuer.url);
  // Tokens stay in the file: neither stream shows them.
  expect(result.stdout + result.stderr).not.toContain(
    signInTo(credentials, owner.administration).refreshToken,
  );
  expect((await stat(cli.file)).mode & 0o777).toBe(0o600);
});

test("login refuses an address the issuer does not name as its own", async () => {
  const owner = await startOwner();
  const cli = await home();
  const other = new URL(owner.issuer.url);
  other.hostname = other.hostname === "localhost" ? "127.0.0.1" : "localhost";

  const result = await cli.run(["login", other.origin]);

  expect(result.code).toBe(1);
  expect(result.stderr).toContain("Sign in at the issuer's own origin");
  await expect(stat(cli.file)).rejects.toThrow();
});

test("every administration action is a command, called as the owner over HTTP", async () => {
  const { cli } = await signedIn();

  const created = await cli.run([
    "create-api-key",
    "--name",
    "from the cli",
    "--permissions",
    JSON.stringify({ [notes.identifier]: ["notes:read"] }),
    "--expires-at",
    "null",
  ]);

  expect(created.code, created.stderr).toBe(0);
  const key = Schema.decodeUnknownSync(Schema.fromJsonString(Created))(created.stdout);

  const listed = await cli.run(["list-api-keys"]);
  expect(listed.code, listed.stderr).toBe(0);
  expect(
    Schema.decodeUnknownSync(Schema.fromJsonString(Listed))(listed.stdout).keys.map(
      (entry) => entry.keyId,
    ),
  ).toContain(key.keyId);

  const deleted = await cli.run(["delete-api-key", "--key-id", key.keyId]);
  expect(deleted.code, deleted.stderr).toBe(0);
  expect(JSON.parse(deleted.stdout)).toEqual({ deleted: true });
});

test("an expired access token is refreshed, and the rotated refresh token is kept", async () => {
  const { owner, cli } = await signedIn();
  const before = signInTo(await cli.stored(), owner.administration);
  await cli.expireAll();

  const listed = await cli.run(["list-api-keys"]);
  expect(listed.code, listed.stderr).toBe(0);

  const after = signInTo(await cli.stored(), owner.administration);
  expect(after.refreshToken).not.toBe(before.refreshToken);
  expect(after.accessToken).not.toBe(before.accessToken);
  expect(Date.parse(after.expiresAt)).toBeGreaterThan(Date.now());
});

test("a sign-in to another resource is kept beside administration's, and `token` prints either", async () => {
  const { owner, cli } = await signedIn();

  const refused = await cli.run(["login", owner.issuer.url, "--resource", notes.identifier]);
  expect(refused.code).toBe(1);
  expect(refused.stderr).toContain(`Name the scopes to ask ${notes.identifier} for with --scope.`);

  const result = await cli.login(owner, "--resource", notes.identifier, "--scope", "notes:read");
  expect(result.code, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    url: owner.issuer.url,
    resource: notes.identifier,
    scope: "notes:read offline_access",
  });

  const notesToken = await cli.run(["token", "--resource", notes.identifier]);
  expect(notesToken.code, notesToken.stderr).toBe(0);
  // The token alone, so `$(clankerauth token …)` is the bearer.
  expect(notesToken.stdout).toBe(`${signInTo(await cli.stored(), notes.identifier).accessToken}\n`);
  expect(audience(notesToken.stdout.trim())).toContain(notes.identifier);

  const administrationToken = await cli.run(["token"]);
  expect(administrationToken.code, administrationToken.stderr).toBe(0);
  expect(audience(administrationToken.stdout.trim())).toContain(owner.administration);

  // Administration still works through its own sign-in.
  expect((await cli.run(["list-api-keys"])).code).toBe(0);
});

test("`token` refreshes each sign-in on its own", async () => {
  const { owner, cli } = await signedIn();
  await cli.login(owner, "--resource", notes.identifier, "--scope", "notes:read");
  const before = await cli.stored();
  await cli.expireAll();

  const printed = await cli.run(["token", "--resource", notes.identifier]);
  expect(printed.code, printed.stderr).toBe(0);

  const after = await cli.stored();
  expect(signInTo(after, notes.identifier).refreshToken).not.toBe(
    signInTo(before, notes.identifier).refreshToken,
  );
  // Administration's was not asked for, so its refresh token is the one it had.
  expect(signInTo(after, owner.administration).refreshToken).toBe(
    signInTo(before, owner.administration).refreshToken,
  );
});

test("`token` for a resource not signed in to says how to sign in", async () => {
  const { owner, cli } = await signedIn();
  const result = await cli.run(["token", "--resource", "http://other.invalid/"]);

  expect(result.code).toBe(1);
  expect(result.stderr).toContain(
    `Not signed in to http://other.invalid/: run \`clankerauth login ${owner.issuer.url} --resource http://other.invalid/ --scope "<scopes>"\` first.`,
  );
  expect(result.stdout).toBe("");
});

test("logout --resource revokes and forgets that sign-in alone", async () => {
  const { owner, cli } = await signedIn();
  await cli.login(owner, "--resource", notes.identifier, "--scope", "notes:read");
  const before = await cli.stored();

  const result = await cli.run(["logout", "--resource", notes.identifier]);

  expect(result.code, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({ signedOut: true });
  expect((await cli.stored()).signIns.map((signIn) => signIn.resource)).toEqual([
    owner.administration,
  ]);
  expect((await cli.run(["token", "--resource", notes.identifier])).code).toBe(1);

  const refused = await refreshDirectly(
    owner,
    before.clientId,
    signInTo(before, notes.identifier).refreshToken,
    notes.identifier,
  );

  expect(refused.status).toBe(400);
});

test("logout revokes every sign-in and forgets them", async () => {
  const { owner, cli } = await signedIn();
  const credentials = await cli.stored();

  const result = await cli.run(["logout"]);

  expect(result.code, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({ signedOut: true });
  await expect(stat(cli.file)).rejects.toThrow();

  const refused = await refreshDirectly(
    owner,
    credentials.clientId,
    signInTo(credentials, owner.administration).refreshToken,
    owner.administration,
  );

  expect(refused.status).toBe(400);
});

test("a file no sign-in can be read from is no sign-in, and login replaces it", async () => {
  const { owner, cli } = await signedIn();
  await writeFile(cli.file, '{"written by": "another version"}', { mode: 0o600 });

  const listed = await cli.run(["list-api-keys"]);
  expect(listed.code).toBe(1);
  expect(listed.stderr).toContain("Not signed in");

  const result = await cli.login(owner);
  expect(result.code, result.stderr).toBe(0);
  expect((await cli.run(["list-api-keys"])).code).toBe(0);

  await writeFile(cli.file, "not json", { mode: 0o600 });
  expect((await cli.run(["logout"])).code).toBe(0);
  await expect(stat(cli.file)).rejects.toThrow();
});

test("signing in to another issuer revokes and forgets the first one's sign-ins", async () => {
  const { owner, cli } = await signedIn();
  const first = await cli.stored();
  const other = await startOwner();

  const result = await cli.login(other);
  expect(result.code, result.stderr).toBe(0);

  const kept = await cli.stored();
  expect(kept.url).toBe(other.issuer.url);
  expect(kept.signIns.map((signIn) => signIn.resource)).toEqual([other.administration]);

  const refused = await refreshDirectly(
    owner,
    first.clientId,
    signInTo(first, owner.administration).refreshToken,
    owner.administration,
  );

  expect(refused.status).toBe(400);
});

test("a read-only sign-in lists and is refused a change", async () => {
  const { owner, cli } = await signedIn("--scope", "clankerauth:read");
  expect(signInTo(await cli.stored(), owner.administration).scope).toBe(
    "clankerauth:read offline_access",
  );

  expect((await cli.run(["list-api-keys"])).code).toBe(0);

  const refused = await cli.run([
    "create-api-key",
    "--name",
    "refused",
    "--permissions",
    JSON.stringify({ [notes.identifier]: ["notes:read"] }),
    "--expires-at",
    "null",
  ]);

  expect(refused.code).toBe(1);
  expect(refused.stderr).toContain("Forbidden");
  expect(refused.stdout).toBe("");
});
