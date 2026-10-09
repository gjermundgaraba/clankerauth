import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Schema } from "effect";
import { afterAll, beforeAll, expect, test } from "vite-plus/test";
import { startDisposableIssuer, type DisposableIssuer } from "@gjermundgaraba/clankerauth-dev";

const binary = fileURLToPath(new URL("../dist/main.mjs", import.meta.url));

const notes = { identifier: "http://notes.invalid/", name: "Notes", scopes: ["notes:read"] };

let issuer: DisposableIssuer;

/** The owner's dashboard session, which approves a sign-in as the browser would. */
let cookie: string;

/** `XDG_CONFIG_HOME` of every run: where the CLI keeps its sign-in. */
let config: string;

beforeAll(async () => {
  issuer = await startDisposableIssuer({
    resources: [notes],
    client: { name: "Unused", redirect: "http://127.0.0.1/unused", resources: [] },
  });
  config = await mkdtemp(join(tmpdir(), "clankerauth-cli-"));

  const signedIn = await fetch(`${issuer.url}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { origin: issuer.url, "content-type": "application/json" },
    body: JSON.stringify({ email: issuer.owner.email, password: issuer.owner.password }),
  });

  expect(signedIn.status).toBe(200);
  cookie = signedIn.headers
    .getSetCookie()
    .map((part) => part.split(";")[0])
    .join("; ");
});

afterAll(async () => {
  await issuer.close();
  await rm(config, { recursive: true, force: true });
});

interface Run {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

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

/** Approve an authorization URL as the signed-in owner's browser, through consent. */
const approve = async (authorization: string) => {
  const authorize = await fetch(authorization, { headers: { cookie }, redirect: "manual" });

  // A script's request is answered with the redirect as JSON, a browser's with a 302.
  const location =
    authorize.status === 302
      ? (authorize.headers.get("location") ?? "")
      : Schema.decodeUnknownSync(Schema.Struct({ url: Schema.String }))(await authorize.json()).url;

  const consentPage = new URL(location, issuer.url);

  expect(consentPage.pathname).toBe("/consent");

  const consent = await fetch(`${issuer.url}/api/auth/oauth2/consent`, {
    method: "POST",
    headers: { cookie, origin: issuer.url, "content-type": "application/json" },
    body: JSON.stringify({ accept: true, oauth_query: consentPage.search.slice(1) }),
  });

  expect(consent.status, await consent.clone().text()).toBe(200);

  const { url } = Schema.decodeUnknownSync(Schema.Struct({ url: Schema.String }))(
    await consent.json(),
  );

  const callback = await fetch(url);
  expect(callback.status).toBe(200);
};

/** Sign in with the packed CLI, approving the URL it prints. */
const login = async (...flags: ReadonlyArray<string>) => {
  let approving: Promise<void> | undefined;

  const result = await run(["login", issuer.url, "--no-browser", ...flags], (stderr, stop) => {
    const url = /https?:\/\/\S+\/oauth2\/authorize\S+/.exec(stderr)?.[0];

    // A failed approval would leave the sign-in waiting for its whole window.
    if (url !== undefined && approving === undefined)
      approving = approve(url).catch((error: Error) => {
        stop();
        throw error;
      });
  });

  await approving;

  return result;
};

const credentialsFile = () => join(config, "clankerauth", "credentials.json");

const Stored = Schema.Struct({
  url: Schema.String,
  clientId: Schema.String,
  accessToken: Schema.String,
  refreshToken: Schema.String,
  expiresAt: Schema.String,
});

const stored = async () =>
  Schema.decodeUnknownSync(Schema.fromJsonString(Stored))(
    await readFile(credentialsFile(), "utf8"),
  );

const Created = Schema.Struct({ keyId: Schema.String, key: Schema.String });

const Listed = Schema.Struct({ keys: Schema.Array(Schema.Struct({ keyId: Schema.String })) });

test("an administration command before signing in says how to sign in", async () => {
  const result = await run(["list-api-keys"]);

  expect(result.code).toBe(1);
  expect(result.stderr).toContain("Not signed in: run `clankerauth login <url>` first.");
  expect(result.stdout).toBe("");
});

test("login signs in through the owner's approval and keeps the sign-in to its owner", async () => {
  const result = await login();

  expect(result.code, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    url: issuer.url,
    scope: "clankerauth:read clankerauth:write offline_access",
  });

  const credentials = await stored();
  expect(credentials.url).toBe(issuer.url);
  // Tokens stay in the file: neither stream shows them.
  expect(result.stdout + result.stderr).not.toContain(credentials.refreshToken);
  expect((await stat(credentialsFile())).mode & 0o777).toBe(0o600);
});

test("every administration action is a command, called as the owner over HTTP", async () => {
  const created = await run([
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

  const listed = await run(["list-api-keys"]);
  expect(listed.code, listed.stderr).toBe(0);
  expect(
    Schema.decodeUnknownSync(Schema.fromJsonString(Listed))(listed.stdout).keys.map(
      (entry) => entry.keyId,
    ),
  ).toContain(key.keyId);

  const deleted = await run(["delete-api-key", "--key-id", key.keyId]);
  expect(deleted.code, deleted.stderr).toBe(0);
  expect(JSON.parse(deleted.stdout)).toEqual({ deleted: true });
});

test("an expired access token is refreshed, and the rotated refresh token is kept", async () => {
  const before = await stored();
  const raw = JSON.parse(await readFile(credentialsFile(), "utf8"));
  await writeFile(
    credentialsFile(),
    JSON.stringify({ ...raw, expiresAt: new Date(0).toISOString() }),
    { mode: 0o600 },
  );

  const listed = await run(["list-api-keys"]);
  expect(listed.code, listed.stderr).toBe(0);

  const after = await stored();
  expect(after.refreshToken).not.toBe(before.refreshToken);
  expect(after.accessToken).not.toBe(before.accessToken);
  expect(Date.parse(after.expiresAt)).toBeGreaterThan(Date.now());
});

test("logout revokes the sign-in and forgets it", async () => {
  const { clientId, refreshToken } = await stored();

  const refresh = () =>
    fetch(`${issuer.issuer}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: refreshToken,
        resource: `${issuer.url}/`,
      }),
    });

  const result = await run(["logout"]);

  expect(result.code, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({ signedOut: true });
  await expect(stat(credentialsFile())).rejects.toThrow();

  // The revoked refresh token no longer refreshes.
  expect((await refresh()).status).toBe(400);
});

test("a read-only sign-in lists and is refused a change", async () => {
  const result = await login("--read-only");
  expect(result.code, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout).scope).toBe("clankerauth:read offline_access");

  expect((await run(["list-api-keys"])).code).toBe(0);

  const refused = await run([
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
