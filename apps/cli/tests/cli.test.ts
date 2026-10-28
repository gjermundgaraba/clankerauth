import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:net";
import type { Server } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { text } from "node:stream/consumers";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { startDisposableIssuer } from "@gjermundgaraba/clankerauth-dev";
import { SignIn } from "@gjermundgaraba/clankerauth-sdk/credentials";
import { Schema } from "effect";
import { describe, expect, it, onTestFinished } from "vite-plus/test";

const SignIns = Schema.Struct({
  signIns: Schema.Record(Schema.String, SignIn),
});

type SignIns = typeof SignIns.Type;

const binary = fileURLToPath(new URL("../dist/main.mjs", import.meta.url));

type Published = Parameters<
  typeof startDisposableIssuer
>[0]["resources"][number];

const notes: Published = {
  identifier: "http://notes.invalid/",
  name: "Notes",
  scopes: ["notes:read"],
};

interface Run {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

const Listening = Schema.Struct({ port: Schema.Int });

const listen = async (server: Server) => {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");

  return Schema.decodeUnknownSync(Listening)(server.address()).port;
};

const listenUntilFinished = async (server: Server) => {
  const port = await listen(server);

  onTestFinished(async () => {
    server.close();
    await once(server, "close");
  });

  return port;
};

const startOwner = async (resources: readonly Published[] = []) => {
  const issuer = await startDisposableIssuer({
    resources: [notes, ...resources],
    client: {
      name: "Unused",
      redirect: "http://127.0.0.1/unused",
      resources: [],
    },
  });

  onTestFinished(async () => {
    await issuer.close();
  });

  const signedIn = await fetch(`${issuer.url}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { origin: issuer.url, "content-type": "application/json" },
    body: JSON.stringify({
      email: issuer.owner.email,
      password: issuer.owner.password,
    }),
  });

  expect(signedIn.status).toBe(200);

  const cookie = signedIn.headers
    .getSetCookie()
    .map((part) => part.split(";")[0])
    .join("; ");

  return { issuer, cookie, administration: `${issuer.url}/` };
};

type Owner = Awaited<ReturnType<typeof startOwner>>;

const startPublishingApp = async (
  scopes: Published["scopes"] = ["app:read", "app:write"]
) => {
  let issuer = "";

  const server = createHttpServer();

  const identifier = `http://127.0.0.1:${await listenUntilFinished(server)}/`;

  server.on("request", (request, response) => {
    if (request.url !== "/.well-known/oauth-protected-resource") {
      response.writeHead(404).end();

      return;
    }

    const published = {
      resource: identifier,
      authorization_servers: [issuer],
    };

    response
      .writeHead(200, { "content-type": "application/json" })
      .end(
        JSON.stringify(
          scopes.length === 0
            ? published
            : { ...published, scopes_supported: scopes }
        )
      );
  });

  const resource: Published = { identifier, name: "App", scopes };

  return {
    resource,
    publish: (named: string) => {
      issuer = named;
    },
  };
};

const startOwnerWithApp = async (scopes?: Published["scopes"]) => {
  const app = await startPublishingApp(scopes);
  const owner = await startOwner([app.resource]);
  app.publish(owner.issuer.issuer);

  return { owner, app: app.resource.identifier, publish: app.publish };
};

const Redirect = Schema.Struct({ url: Schema.String });

const approve = async ({ issuer, cookie }: Owner, authorization: string) => {
  const authorize = await fetch(authorization, {
    headers: { cookie },
    redirect: "manual",
  });

  const location =
    authorize.status === 302
      ? (authorize.headers.get("location") ?? "")
      : Schema.decodeUnknownSync(Redirect)(await authorize.json()).url;

  const consentPage = new URL(location, issuer.url);

  expect(consentPage.pathname).toBe("/consent");

  const consent = await fetch(`${issuer.url}/api/auth/oauth2/consent`, {
    method: "POST",
    headers: { cookie, origin: issuer.url, "content-type": "application/json" },
    body: JSON.stringify({
      accept: true,
      oauth_query: consentPage.search.slice(1),
    }),
  });

  expect(consent.status, await consent.clone().text()).toBe(200);

  const callback = await fetch(
    Schema.decodeUnknownSync(Redirect)(await consent.json()).url
  );

  expect(callback.status).toBe(200);
  await expect(callback.text()).resolves.toContain("Return to the terminal.");
};

const signInTo = (signIns: SignIns, resource: string): SignIn => {
  const found = signIns.signIns[resource];

  if (found === undefined) {
    throw new Error(`No sign-in to ${resource}`);
  }

  return found;
};

const audience = (jwt: string) =>
  Schema.decodeUnknownSync(
    Schema.Struct({
      aud: Schema.Union([Schema.String, Schema.Array(Schema.String)]),
    })
  )(JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString()))
    .aud;

const home = async () => {
  const config = await mkdtemp(path.join(tmpdir(), "clankerauth-cli-"));

  onTestFinished(async () => {
    await rm(config, { recursive: true, force: true });
  });

  const file = path.join(config, "clankerauth", "sign-ins.json");

  const run = async (
    args: readonly string[],
    onStderr?: (text: string, stop: () => void) => void,
    env: Readonly<Record<string, string>> = {}
  ): Promise<Run> => {
    const child = spawn(process.execPath, [binary, ...args], {
      env: { ...process.env, XDG_CONFIG_HOME: config, ...env },
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
      onStderr?.(stderr, () => {
        child.kill();
      });
    });

    await once(child, "close");

    return { code: child.exitCode, stdout, stderr };
  };

  const approving = async (
    owner: Owner,
    args: readonly string[],
    env: Readonly<Record<string, string>> = {}
  ) => {
    let approval: Promise<void> | undefined;

    const approveOrStop = async (url: string, stop: () => void) => {
      try {
        await approve(owner, url);
      } catch (error) {
        stop();
        throw error;
      }
    };

    const result = await run(
      ["login", ...args],
      (stderr, stop) => {
        const url = /https?:\/\/\S+\/oauth2\/authorize\S+/u.exec(stderr)?.[0];

        if (url !== undefined && approval === undefined) {
          approval = approveOrStop(url, stop);
        }
      },
      env
    );

    await approval;

    return result;
  };

  const loginAt = async (
    owner: Owner,
    url: string,
    ...flags: readonly string[]
  ) => await approving(owner, [url, "--no-browser", ...flags]);

  const stored = async () =>
    Schema.decodeSync(Schema.fromJsonString(SignIns))(
      await readFile(file, "utf-8")
    );

  const rewrite = async (change: (signIn: SignIn) => SignIn) => {
    const signIns = await stored();

    await writeFile(
      file,
      JSON.stringify({
        ...signIns,
        signIns: Object.fromEntries(
          Object.entries(signIns.signIns).map(([resource, signIn]) => [
            resource,
            change(signIn),
          ])
        ),
      }),
      { mode: 0o600 }
    );
  };

  const expireAll = async () => {
    await rewrite((signIn) => ({
      ...signIn,
      expiresAt: new Date(0).toISOString(),
    }));
  };

  const login = async (owner: Owner, ...flags: readonly string[]) =>
    await loginAt(owner, owner.issuer.url, ...flags);

  return {
    config,
    file,
    run,
    approving,
    login,
    loginAt,
    stored,
    rewrite,
    expireAll,
  };
};

const signedIn = async (...flags: readonly string[]) => {
  const owner = await startOwner();
  const cli = await home();
  const result = await cli.login(owner, ...flags);

  expect(result.code, result.stderr).toBe(0);

  return { owner, cli };
};

const signedInToApp = async () => {
  const { owner, app } = await startOwnerWithApp();
  const cli = await home();

  for (const url of [owner.issuer.url, app]) {
    const result = await cli.loginAt(owner, url);
    expect(result.code, result.stderr).toBe(0);
  }

  return { owner, app, cli };
};

const refreshDirectly = async (
  { issuer }: Owner,
  clientId: string,
  refreshToken: string,
  resource: string
) =>
  await fetch(`${issuer.issuer}/oauth2/token`, {
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

const Listed = Schema.Struct({
  keys: Schema.Array(Schema.Struct({ keyId: Schema.String })),
});

const slowerThanProcessStartsMillis = 500;

const slowTokenEndpoint = async ({ issuer }: Owner) => {
  let requests = 0;

  const forward = async (
    request: IncomingMessage,
    response: ServerResponse
  ) => {
    const body = await text(request);
    await sleep(slowerThanProcessStartsMillis);

    const answer = await fetch(`${issuer.issuer}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": request.headers["content-type"] ?? "" },
      body,
    });

    response
      .writeHead(answer.status, {
        "content-type": answer.headers.get("content-type") ?? "",
      })
      .end(await answer.text());
  };

  const server = createHttpServer((request, response) => {
    requests += 1;
    forward(request, response).catch(() => {
      if (response.headersSent) {
        response.destroy();
      } else {
        response.writeHead(502).end();
      }
    });
  });

  const port = await listenUntilFinished(server);

  return { url: `http://127.0.0.1:${port}/token`, requests: () => requests };
};

describe("the clankerauth CLI", () => {
  it("an administration command before signing in says how to sign in", async () => {
    const cli = await home();
    const result = await cli.run(["list-api-keys"]);

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      "Not signed in: run `clankerauth login <url>` first."
    );
    expect(result.stdout).toBe("");
  });

  it("--no-browser has no negated form", async () => {
    const cli = await home();

    const result = await cli.run([
      "login",
      "http://notes.invalid/",
      "--no-no-browser",
    ]);

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("Unrecognized flag: --no-no-browser");
  });

  it("login signs in through the owner's approval and keeps its tokens in an owner-only file, not its output", async () => {
    const owner = await startOwner();
    const cli = await home();
    const result = await cli.login(owner);

    expect(result.code, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toStrictEqual({
      url: owner.issuer.url,
      resource: owner.administration,
      scope: "clankerauth:read clankerauth:write offline_access",
    });

    const signIn = signInTo(await cli.stored(), owner.administration);
    expect(signIn.url).toBe(owner.issuer.url);
    expect(result.stdout + result.stderr).not.toContain(signIn.refreshToken);
    const { mode } = await stat(cli.file);
    expect(mode & 0o777).toBe(0o600);
  });

  it("login opens the approval page in the browser, and prints its URL", async () => {
    const owner = await startOwner();
    const cli = await home();
    const opened = path.join(cli.config, "opened");
    const bin = path.join(cli.config, "bin");

    await mkdir(bin);
    await writeFile(
      path.join(bin, process.platform === "darwin" ? "open" : "xdg-open"),
      `#!/bin/sh\necho "$1" > "${opened}"\n`,
      { mode: 0o755 }
    );

    const result = await cli.approving(owner, [owner.issuer.url], {
      PATH: `${bin}:${process.env["PATH"] ?? ""}`,
    });

    expect(result.code, result.stderr).toBe(0);

    const printed = /https?:\/\/\S+\/oauth2\/authorize\S+/u.exec(
      result.stderr
    )?.[0];

    expect(printed).toBeDefined();
    await expect
      .poll(
        async () =>
          await readFile(opened, "utf-8").then(
            (url) => url.trim(),
            () => {}
          )
      )
      .toBe(printed);
  });

  it("login refuses an address the resource is not published at, and says which it is", async () => {
    const owner = await startOwner();
    const cli = await home();
    const other = new URL(owner.issuer.url);
    other.hostname = other.hostname === "localhost" ? "127.0.0.1" : "localhost";

    const result = await cli.run(["login", other.origin]);

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      `Discovery at ${other.origin}: it publishes the resource ${owner.administration}: sign in to that address`
    );
    await expect(stat(cli.file)).rejects.toThrow("ENOENT");
  });

  it("login at an address nothing answers says why", async () => {
    const listener = createServer();
    const port = await listen(listener);
    listener.close();
    await once(listener, "close");

    const cli = await home();
    const result = await cli.run(["login", `http://127.0.0.1:${port}`]);

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      `Discovery at http://127.0.0.1:${port}: fetch failed (connect ECONNREFUSED 127.0.0.1:${port})`
    );
  });

  it("login at an application naming a malformed issuer says so", async () => {
    const { app, publish } = await startOwnerWithApp();
    publish("not a url");

    const cli = await home();
    const result = await cli.run(["login", app]);

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      `Discovery at ${new URL(app).origin}: its authorization server not a url is no URL`
    );
  });

  it("login at an application publishing no scopes asks for offline_access alone", async () => {
    const { owner, app } = await startOwnerWithApp([]);
    const cli = await home();
    const result = await cli.loginAt(owner, app);

    expect(result.code, result.stderr).toBe(0);
    expect(signInTo(await cli.stored(), app).scope).toBe("offline_access");
    const token = await cli.run(["token", app]);
    expect(token.code).toBe(0);

    await cli.rewrite((signIn) => ({
      ...signIn,
      refreshToken: "revoked",
      expiresAt: new Date(0).toISOString(),
    }));

    const refused = await cli.run(["token", app]);
    expect(refused.stderr).toContain(`Run \`clankerauth login ${app}\` again.`);
  });

  it("login again revokes the sign-in it replaces", async () => {
    const { owner, cli } = await signedIn();
    const replaced = signInTo(await cli.stored(), owner.administration);

    const result = await cli.login(owner);
    expect(result.code, result.stderr).toBe(0);

    const refused = await refreshDirectly(
      owner,
      replaced.clientId,
      replaced.refreshToken,
      owner.administration
    );

    expect(refused.status).toBe(400);

    const listed = await cli.run(["list-api-keys"]);
    expect(listed.code).toBe(0);
  });

  it("every administration action is a command, called as the owner over HTTP", async () => {
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

    const key = Schema.decodeSync(Schema.fromJsonString(Created))(
      created.stdout
    );

    const listed = await cli.run(["list-api-keys"]);
    expect(listed.code, listed.stderr).toBe(0);
    expect(
      Schema.decodeSync(Schema.fromJsonString(Listed))(listed.stdout).keys.map(
        (entry) => entry.keyId
      )
    ).toContain(key.keyId);

    const deleted = await cli.run(["delete-api-key", "--key-id", key.keyId]);
    expect(deleted.code, deleted.stderr).toBe(0);
    expect(JSON.parse(deleted.stdout)).toStrictEqual({ deleted: true });
  });

  it("an expired access token is refreshed, and the rotated refresh token is kept", async () => {
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

  it("login at an application's URL signs in to the resource it publishes, beside administration", async () => {
    const { owner, app, cli } = await signedInToApp();

    const { signIns } = await cli.stored();
    expect(Object.keys(signIns)).toStrictEqual([owner.administration, app]);
    expect(signInTo(await cli.stored(), app).scope).toBe(
      "app:read app:write offline_access"
    );

    const appToken = await cli.run(["token", app]);
    expect(appToken.code, appToken.stderr).toBe(0);
    expect(appToken.stdout).toBe(
      `${signInTo(await cli.stored(), app).accessToken}\n`
    );
    expect(audience(appToken.stdout.trim())).toContain(app);

    const administrationToken = await cli.run(["token"]);
    expect(administrationToken.code, administrationToken.stderr).toBe(0);
    expect(audience(administrationToken.stdout.trim())).toContain(
      owner.administration
    );

    const listed = await cli.run(["list-api-keys"]);
    expect(listed.code).toBe(0);
  });

  it("eight `token` runs at once refresh an expired sign-in once, and all print its token", async () => {
    const { owner, cli } = await signedIn();
    const before = signInTo(await cli.stored(), owner.administration);
    const proxy = await slowTokenEndpoint(owner);

    await cli.rewrite((signIn) => ({
      ...signIn,
      server: { ...signIn.server, token_endpoint: proxy.url },
      expiresAt: new Date(0).toISOString(),
    }));

    const runs = await Promise.all(
      Array.from({ length: 8 }, async () => await cli.run(["token"]))
    );

    for (const run of runs) {
      expect(run.code, run.stderr).toBe(0);
    }

    expect(proxy.requests()).toBe(1);
    const after = signInTo(await cli.stored(), owner.administration);
    expect(new Set(runs.map((run) => run.stdout))).toStrictEqual(
      new Set([`${after.accessToken}\n`])
    );
    expect(after.refreshToken).not.toBe(before.refreshToken);

    const kept = await refreshDirectly(
      owner,
      after.clientId,
      after.refreshToken,
      owner.administration
    );

    expect(kept.status).toBe(200);
  });

  it("`token` refreshes each sign-in on its own", async () => {
    const { owner, app, cli } = await signedInToApp();
    const before = await cli.stored();
    await cli.expireAll();

    const printed = await cli.run(["token", app]);
    expect(printed.code, printed.stderr).toBe(0);

    const after = await cli.stored();
    expect(signInTo(after, app).refreshToken).not.toBe(
      signInTo(before, app).refreshToken
    );
    expect(signInTo(after, owner.administration).refreshToken).toBe(
      signInTo(before, owner.administration).refreshToken
    );
  });

  it("`token` for a resource not signed in to says how to sign in", async () => {
    const { cli } = await signedIn();
    const result = await cli.run(["token", "http://other.invalid/some/page"]);

    expect(result.code).toBe(1);
    expect(result.stderr).toContain(
      "Not signed in to http://other.invalid/: run `clankerauth login http://other.invalid/` first."
    );
    expect(result.stdout).toBe("");
  });

  it("a refused refresh names the login that asks for the same scopes again", async () => {
    const { owner, cli } = await signedIn("--scope", "clankerauth:read");
    await cli.rewrite((signIn) => ({
      ...signIn,
      refreshToken: "revoked",
      expiresAt: new Date(0).toISOString(),
    }));

    const hint = `Run \`clankerauth login ${owner.administration} --scope "clankerauth:read"\` again.`;

    for (const command of ["token", "list-api-keys"]) {
      const result = await cli.run([command]);

      expect(result.code).toBe(1);
      expect(result.stderr).toContain(hint);
    }
  });

  it("logout at a URL revokes and forgets the sign-in it is under alone", async () => {
    const { owner, app, cli } = await signedInToApp();
    const leaving = signInTo(await cli.stored(), app);

    const result = await cli.run(["logout", `${app}some/page`]);

    expect(result.code, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toStrictEqual({ signedOut: true });
    const { signIns } = await cli.stored();
    expect(Object.keys(signIns)).toStrictEqual([owner.administration]);
    const token = await cli.run(["token", app]);
    expect(token.code).toBe(1);

    const refused = await refreshDirectly(
      owner,
      leaving.clientId,
      leaving.refreshToken,
      app
    );

    expect(refused.status).toBe(400);
  });

  it("logout revokes every sign-in and forgets them", async () => {
    const { owner, cli } = await signedIn();
    const signIn = signInTo(await cli.stored(), owner.administration);

    const result = await cli.run(["logout"]);

    expect(result.code, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toStrictEqual({ signedOut: true });
    await expect(stat(cli.file)).rejects.toThrow("ENOENT");

    const refused = await refreshDirectly(
      owner,
      signIn.clientId,
      signIn.refreshToken,
      owner.administration
    );

    expect(refused.status).toBe(400);
  });

  it("a file no sign-in can be read from is no sign-in, and login replaces it", async () => {
    const { owner, cli } = await signedIn();
    await writeFile(cli.file, '{"url": "written by 0.23"}', { mode: 0o600 });

    const listed = await cli.run(["list-api-keys"]);
    expect(listed.code).toBe(1);
    expect(listed.stderr).toContain("Not signed in");

    const result = await cli.login(owner);
    expect(result.code, result.stderr).toBe(0);
    const relisted = await cli.run(["list-api-keys"]);
    expect(relisted.code).toBe(0);

    await writeFile(cli.file, "not json", { mode: 0o600 });
    const loggedOut = await cli.run(["logout"]);
    expect(loggedOut.code).toBe(0);
    await expect(stat(cli.file)).rejects.toThrow("ENOENT");
  });

  it("sign-ins at two issuers are kept side by side, and CLANKERAUTH_URL picks which to administer", async () => {
    const { owner, cli } = await signedIn();
    const other = await startOwner();
    const result = await cli.login(other);
    expect(result.code, result.stderr).toBe(0);

    const { signIns } = await cli.stored();
    expect(Object.keys(signIns)).toStrictEqual([
      owner.administration,
      other.administration,
    ]);

    const ambiguous = await cli.run(["list-api-keys"]);
    expect(ambiguous.code).toBe(1);
    expect(ambiguous.stderr).toContain("name one with CLANKERAUTH_URL");

    const listed = await cli.run(["list-api-keys"], undefined, {
      CLANKERAUTH_URL: owner.issuer.url,
    });

    expect(listed.code, listed.stderr).toBe(0);

    const misnamed = await cli.run(["list-api-keys"], undefined, {
      CLANKERAUTH_URL: "issuer",
    });

    expect(misnamed.code).toBe(1);
    expect(misnamed.stderr).toContain("CLANKERAUTH_URL is no issuer URL");

    const first = signInTo(await cli.stored(), owner.administration);

    const kept = await refreshDirectly(
      owner,
      first.clientId,
      first.refreshToken,
      owner.administration
    );

    expect(kept.status).toBe(200);
  });

  it("an administration key in CLANKERAUTH_TOKEN administers without a sign-in", async () => {
    const { owner, cli } = await signedIn();

    const created = await cli.run([
      "create-api-key",
      "--name",
      "deployer",
      "--permissions",
      JSON.stringify({
        [owner.administration]: ["clankerauth:read", "clankerauth:write"],
      }),
      "--expires-at",
      "null",
    ]);

    expect(created.code, created.stderr).toBe(0);

    const key = Schema.decodeSync(Schema.fromJsonString(Created))(
      created.stdout
    );

    const unattended = await home();

    const env = {
      CLANKERAUTH_TOKEN: key.key,
      CLANKERAUTH_URL: owner.issuer.url,
    };

    const listed = await unattended.run(["list-api-keys"], undefined, env);
    expect(listed.code, listed.stderr).toBe(0);
    expect(listed.stdout).toContain(key.keyId);
    await expect(stat(unattended.file)).rejects.toThrow("ENOENT");

    const unnamed = await unattended.run(["list-api-keys"], undefined, {
      CLANKERAUTH_TOKEN: key.key,
    });

    expect(unnamed.code).toBe(1);
    expect(unnamed.stderr).toContain(
      "CLANKERAUTH_TOKEN is set without CLANKERAUTH_URL"
    );

    const opaque = await unattended.run(["list-api-keys"], undefined, {
      CLANKERAUTH_TOKEN: key.key,
      CLANKERAUTH_URL: "mailto:owner@example.com",
    });

    expect(opaque.code).toBe(1);
    expect(opaque.stderr).toContain("CLANKERAUTH_URL is no issuer URL");

    const deleted = await unattended.run(
      ["delete-api-key", "--key-id", key.keyId],
      undefined,
      env
    );

    expect(deleted.code, deleted.stderr).toBe(0);

    const refused = await unattended.run(["list-api-keys"], undefined, env);
    expect(refused.code).toBe(1);
    expect(refused.stderr).toContain("Unauthenticated");
  });

  it("a read-only sign-in lists and is refused a change", async () => {
    const { owner, cli } = await signedIn("--scope", "clankerauth:read");
    expect(signInTo(await cli.stored(), owner.administration).scope).toBe(
      "clankerauth:read offline_access"
    );

    const listed = await cli.run(["list-api-keys"]);
    expect(listed.code).toBe(0);

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
});
