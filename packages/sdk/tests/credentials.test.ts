import assert from "node:assert/strict";
import { once } from "node:events";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { text } from "node:stream/consumers";
import { setTimeout as sleep } from "node:timers/promises";

import { it } from "@effect/vitest";
import * as Action from "@gjermundgaraba/effect-actions/Action";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as Testing from "@gjermundgaraba/effect-actions/Testing";
import {
  Config,
  ConfigProvider,
  Effect,
  Fiber,
  Redacted,
  Schema,
} from "effect";
import lockfile from "proper-lockfile";
import { expect } from "vite-plus/test";

import * as Credentials from "../src/credentials.ts";

interface Fake {
  url: string;
  readonly refreshes: URLSearchParams[];
  readonly revocations: URLSearchParams[];
  refusal: { readonly status: number; readonly body: Schema.Json } | undefined;
  delay: number;
}

const fakeIssuer = Effect.acquireRelease(
  Effect.gen(function* () {
    const state: Fake = {
      url: "",
      refreshes: [],
      revocations: [],
      refusal: undefined,
      delay: 100,
    };

    const respond = async (
      request: IncomingMessage,
      response: ServerResponse
    ) => {
      const json = (status: number, value: Schema.Json) =>
        response
          .writeHead(status, { "content-type": "application/json" })
          .end(JSON.stringify(value));

      const form = new URLSearchParams(await text(request));

      if (request.url === "/api/auth/oauth2/revoke") {
        state.revocations.push(form);

        return response.writeHead(200).end();
      }

      if (request.url !== "/api/auth/oauth2/token") {
        return json(404, { error: "Not found" });
      }

      state.refreshes.push(form);
      await sleep(state.delay);

      if (state.refusal !== undefined) {
        return json(state.refusal.status, state.refusal.body);
      }

      const n = state.refreshes.length;

      return json(200, {
        access_token: `access-${n}`,
        refresh_token: `refresh-${n}`,
        expires_in: 900,
        scope: "notes:read offline_access",
        token_type: "Bearer",
      });
    };

    const server = createServer((request, response) => {
      void respond(request, response);
    });

    server.listen(0, "127.0.0.1");
    yield* Effect.promise(async () => {
      await once(server, "listening");
    });
    const address = server.address();
    assert.ok(
      address !== null && address instanceof Object && "port" in address
    );
    state.url = `http://127.0.0.1:${address.port}`;

    return { state, server };
  }),
  ({ server }) =>
    Effect.promise(async () => {
      server.closeAllConnections();
      await server[Symbol.asyncDispose]();
    })
).pipe(Effect.map(({ state }) => state));

const ownConfigHome = Effect.acquireRelease(
  Effect.gen(function* () {
    const previous = process.env["XDG_CONFIG_HOME"];

    const directory = yield* Effect.promise(
      async () => await mkdtemp(nodePath.join(tmpdir(), "clankerauth-sdk-"))
    );

    process.env["XDG_CONFIG_HOME"] = directory;

    return { directory, previous };
  }),
  ({ directory, previous }) =>
    Effect.promise(async () => {
      if (previous === undefined) {
        delete process.env["XDG_CONFIG_HOME"];
      } else {
        process.env["XDG_CONFIG_HOME"] = previous;
      }

      await rm(directory, { recursive: true, force: true });
    })
).pipe(Effect.as(undefined));

const expired = new Date(0).toISOString();

const later = () => new Date(Date.now() + 600_000).toISOString();

const signInAt = (
  issuer: Fake,
  resource: string,
  expiresAt: string,
  tokenEndpoint = `${issuer.url}/api/auth/oauth2/token`
): Credentials.SignIn => ({
  resource,
  url: issuer.url,
  server: {
    issuer: `${issuer.url}/api/auth`,
    authorization_endpoint: `${issuer.url}/api/auth/oauth2/authorize`,
    token_endpoint: tokenEndpoint,
    registration_endpoint: `${issuer.url}/api/auth/oauth2/register`,
    revocation_endpoint: `${issuer.url}/api/auth/oauth2/revoke`,
  },
  clientId: "cli-client",
  scope: "notes:read offline_access",
  accessToken: "access-0",
  refreshToken: "refresh-0",
  expiresAt,
});

const kept = (...signIns: readonly Credentials.SignIn[]) =>
  Effect.promise(async () => {
    const file = Credentials.path();
    await mkdir(nodePath.join(file, ".."), { recursive: true, mode: 0o700 });
    await writeFile(
      file,
      JSON.stringify({
        signIns: Object.fromEntries(
          signIns.map((signIn) => [signIn.resource, signIn])
        ),
      }),
      { mode: 0o600 }
    );
  });

const stored = (resource: string) =>
  Effect.map(Credentials.list, (signIns) => {
    const signIn = signIns.find((each) => each.resource === resource);
    assert.ok(signIn !== undefined);

    return signIn;
  });

const app = (issuer: Fake) =>
  `${issuer.url.replace("127.0.0.1", "localhost")}/`;

it.live("a current sign-in's token is given without a refresh", () =>
  Effect.scoped(
    Effect.gen(function* () {
      const issuer = yield* fakeIssuer;
      yield* ownConfigHome;
      yield* kept(signInAt(issuer, app(issuer), later()));

      const bearer = yield* Credentials.token({
        url: `${app(issuer)}some/page`,
      });

      expect(Redacted.value(bearer)).toBe("access-0");
      expect(issuer.refreshes).toStrictEqual([]);
    })
  )
);

it.live(
  "eight concurrent requests refresh an expired sign-in once, and keep its rotation",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;
        yield* kept(signInAt(issuer, app(issuer), expired));

        const tokens = yield* Effect.all(
          Array.from({ length: 8 }, () =>
            Credentials.token({ url: app(issuer) })
          ),
          { concurrency: "unbounded" }
        );

        expect(tokens.map(Redacted.value)).toStrictEqual(
          Array.from({ length: 8 }, () => "access-1")
        );
        expect(issuer.refreshes).toHaveLength(1);
        expect(Object.fromEntries(issuer.refreshes[0] ?? [])).toMatchObject({
          grant_type: "refresh_token",
          refresh_token: "refresh-0",
          client_id: "cli-client",
          resource: app(issuer),
        });

        const signIn = yield* stored(app(issuer));
        expect(signIn.refreshToken).toBe("refresh-1");
        expect(Date.parse(signIn.expiresAt)).toBeGreaterThan(
          Date.now() + 800_000
        );
      })
    )
);

it.live(
  "a lock another process holds is waited for, and the token it saved is read",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;
        yield* kept(signInAt(issuer, app(issuer), expired));

        const release = yield* Effect.promise(
          async () =>
            await lockfile.lock(Credentials.path(), { realpath: false })
        );

        const waiting = yield* Effect.forkChild(
          Credentials.token({ url: app(issuer) })
        );

        yield* Effect.sleep("300 millis");
        yield* kept(signInAt(issuer, app(issuer), later()));
        yield* Effect.promise(async () => {
          await release();
        });

        expect(Redacted.value(yield* Fiber.join(waiting))).toBe("access-0");
        expect(issuer.refreshes).toStrictEqual([]);
      })
    )
);

it.live("a lock left by a process that died is broken", () =>
  Effect.scoped(
    Effect.gen(function* () {
      const issuer = yield* fakeIssuer;
      yield* ownConfigHome;
      yield* kept(signInAt(issuer, app(issuer), expired));
      const lock = `${Credentials.path()}.lock`;
      yield* Effect.promise(async () => {
        await mkdir(lock);
      });
      const longAgo = new Date(Date.now() - 60_000);
      yield* Effect.promise(async () => {
        await utimes(lock, longAgo, longAgo);
      });

      expect(
        Redacted.value(yield* Credentials.token({ url: app(issuer) }))
      ).toBe("access-1");
      expect(issuer.refreshes).toHaveLength(1);
    })
  )
);

it.live(
  "a refused refresh asks for a sign-in again with the scopes it had",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;
        yield* kept(signInAt(issuer, app(issuer), expired));
        issuer.refusal = {
          status: 400,
          body: {
            error: "invalid_grant",
            error_description: "refresh token revoked",
          },
        };

        const refused = yield* Effect.flip(
          Credentials.token({ url: app(issuer) })
        );

        assert.ok(refused instanceof Credentials.SignInRequired);
        expect(refused.command).toBe(
          `clankerauth login ${app(issuer)} --scope "notes:read"`
        );
        expect(refused.message).toBe(
          `Refresh: invalid_grant: refresh token revoked. Run \`${refused.command}\` again.`
        );

        issuer.refusal = {
          status: 503,
          body: { error: "temporarily_unavailable" },
        };

        const unavailable = yield* Effect.flip(
          Credentials.token({ url: app(issuer) })
        );

        assert.ok(unavailable instanceof Credentials.TokenUnavailable);
        expect(unavailable.message).toContain("(HTTP 503)");
        expect((yield* stored(app(issuer))).refreshToken).toBe("refresh-0");
      })
    )
);

it.live(
  "a refresh token is never sent over plain HTTP to an issuer signed in to over HTTPS",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;

        yield* kept({
          ...signInAt(issuer, "https://notes.example/", expired),
          url: "https://clankerauth.example",
        });

        const refused = yield* Effect.flip(
          Credentials.token({ url: "https://notes.example" })
        );

        assert.ok(refused instanceof Credentials.TokenUnavailable);
        expect(issuer.refreshes).toStrictEqual([]);
      })
    )
);

it.live("without a sign-in, the command to run is named", () =>
  Effect.scoped(
    Effect.gen(function* () {
      yield* ownConfigHome;

      const missing = yield* Effect.flip(
        Credentials.token({ url: "https://notes.example/a" })
      );

      assert.ok(missing instanceof Credentials.SignInRequired);
      expect(missing.message).toBe(
        "Not signed in to https://notes.example/: run `clankerauth login https://notes.example/` first."
      );

      const notUrl = yield* Effect.flip(
        Credentials.token({ url: "not a url" })
      );

      expect(notUrl).toBeInstanceOf(Credentials.TokenUnavailable);
    })
  )
);

it.live(
  "a token the environment gives is returned instead of the sign-in",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;
        yield* kept(signInAt(issuer, app(issuer), expired));
        const token = Config.Redacted("NOTES_TOKEN");

        const given = yield* Credentials.token({
          url: app(issuer),
          token,
        }).pipe(
          Effect.provide(
            ConfigProvider.layer(
              ConfigProvider.fromEnvRecord({ NOTES_TOKEN: "ck_given" })
            )
          )
        );

        expect(Redacted.value(given)).toBe("ck_given");

        const unset = yield* Credentials.token({
          url: app(issuer),
          token,
        }).pipe(
          Effect.provide(ConfigProvider.layer(ConfigProvider.fromEnvRecord({})))
        );

        expect(Redacted.value(unset)).toBe("access-1");
      })
    )
);

it.live(
  "sign-ins at two issuers are kept side by side, and signing out of one revokes it alone",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const first = yield* fakeIssuer;
        const second = yield* fakeIssuer;
        yield* ownConfigHome;

        yield* kept(
          {
            ...signInAt(first, app(first), later()),
            refreshToken: "first-refresh",
          },
          { ...signInAt(second, app(second), later()), accessToken: "second" }
        );

        expect(
          Redacted.value(yield* Credentials.token({ url: app(first) }))
        ).toBe("access-0");
        expect(
          Redacted.value(yield* Credentials.token({ url: app(second) }))
        ).toBe("second");

        expect(
          yield* Credentials.signOut(`${app(first)}some/page`)
        ).toStrictEqual({
          signedOut: true,
        });
        expect(
          first.revocations.map((form) => form.get("token"))
        ).toStrictEqual(["first-refresh"]);
        expect(second.revocations).toStrictEqual([]);
        expect(
          (yield* Credentials.list).map((signIn) => signIn.resource)
        ).toStrictEqual([app(second)]);

        expect(yield* Credentials.signOut()).toStrictEqual({ signedOut: true });
        expect(
          yield* Effect.promise(
            async () => await readFile(Credentials.path()).catch(() => "gone")
          )
        ).toBe("gone");
      })
    )
);

it.live(
  "the most specific sign-in whose resource holds the URL gives its token",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;

        yield* kept(signInAt(issuer, app(issuer), later()), {
          ...signInAt(issuer, `${app(issuer)}api`, later()),
          accessToken: "api",
        });

        const tokenAt = (path: string) =>
          Effect.map(
            Credentials.token({ url: `${app(issuer)}${path}` }),
            Redacted.value
          );

        expect(yield* tokenAt("api/notes?page=2#top")).toBe("api");
        expect(yield* tokenAt("api")).toBe("api");
        expect(yield* tokenAt("apiary")).toBe("access-0");
        expect(yield* tokenAt("")).toBe("access-0");
      })
    )
);

it.live(
  "signing out waits for a refresh in flight, and revokes the token it saved",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;
        yield* kept(signInAt(issuer, app(issuer), expired));

        const refreshing = yield* Effect.forkChild(
          Credentials.token({ url: app(issuer) })
        );

        yield* Effect.sleep("30 millis");

        expect(yield* Credentials.signOut(app(issuer))).toStrictEqual({
          signedOut: true,
        });
        expect(Redacted.value(yield* Fiber.join(refreshing))).toBe("access-1");
        expect(
          issuer.revocations.map((form) => form.get("token"))
        ).toStrictEqual(["refresh-1"]);
        expect(yield* Credentials.list).toStrictEqual([]);
      })
    )
);

it.live(
  "an interrupted refresh still keeps the refresh token the issuer rotated",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;
        yield* kept(signInAt(issuer, app(issuer), expired));

        const refreshing = yield* Effect.forkChild(
          Credentials.token({ url: app(issuer) })
        );

        yield* Effect.sleep("30 millis");
        yield* Fiber.interrupt(refreshing);

        expect(issuer.refreshes).toHaveLength(1);
        expect((yield* stored(app(issuer))).refreshToken).toBe("refresh-1");
      })
    )
);

const tookOver = (issuer: Fake, ...signIns: readonly Credentials.SignIn[]) =>
  Effect.gen(function* () {
    issuer.delay = 500;

    const refreshing = yield* Effect.forkChild(
      Credentials.token({ url: app(issuer) })
    );

    yield* Effect.sleep("100 millis");
    yield* Effect.promise(async () => {
      await rm(`${Credentials.path()}.lock`, { recursive: true });
    });
    yield* kept(...signIns);

    return Redacted.value(yield* Fiber.join(refreshing));
  });

it.live(
  "a refresh whose lock another process took over keeps its rotation and that process's sign-ins",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;
        yield* kept(signInAt(issuer, app(issuer), expired));

        const other = {
          ...signInAt(issuer, "https://other.example/", later()),
          accessToken: "other",
        };

        expect(
          yield* tookOver(issuer, signInAt(issuer, app(issuer), expired), other)
        ).toBe("access-1");

        expect((yield* stored(app(issuer))).refreshToken).toBe("refresh-1");
        expect((yield* stored("https://other.example/")).accessToken).toBe(
          "other"
        );
      })
    )
);

it.live(
  "a refresh whose lock another process took over keeps the sign-in it saved meanwhile",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;
        yield* kept(signInAt(issuer, app(issuer), expired));

        const again = {
          ...signInAt(issuer, app(issuer), later()),
          refreshToken: "signed-in-again",
        };

        expect(yield* tookOver(issuer, again)).toBe("access-1");
        expect((yield* stored(app(issuer))).refreshToken).toBe(
          "signed-in-again"
        );
      })
    )
);

const Echo = Action.make("echo", {
  description: "Answer the request's Authorization header",
  caller: Action.Anyone,
  readOnly: true,
  success: Schema.String,
});

const EchoHttp = ActionHttp.make([Echo]);

const echoing = Testing.layer(async (request) =>
  Response.json(request.headers.get("authorization"))
);

it.live(
  "a client authorizing its requests sends a current token, and fails with the sign-in it lacks",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const issuer = yield* fakeIssuer;
        yield* ownConfigHome;
        yield* kept(signInAt(issuer, app(issuer), expired));

        const signedIn = yield* ActionHttp.client(EchoHttp, {
          baseUrl: app(issuer),
          transformClient: Credentials.authorizing({ url: app(issuer) }),
        });

        expect(yield* signedIn.echo()).toBe("Bearer access-1");
        expect(yield* signedIn.echo()).toBe("Bearer access-1");
        expect(issuer.refreshes).toHaveLength(1);

        const signedOut = yield* ActionHttp.client(EchoHttp, {
          baseUrl: "https://other.example",
          transformClient: Credentials.authorizing({
            url: "https://other.example/",
          }),
        });

        const command = yield* signedOut
          .echo()
          .pipe(
            Effect.catchTag("SignInRequired", (error) =>
              Effect.succeed(error.command)
            )
          );

        expect(command).toBe("clankerauth login https://other.example/");
      }).pipe(Effect.provide(echoing))
    )
);

it.live("a file no version can read is no sign-in", () =>
  Effect.scoped(
    Effect.gen(function* () {
      yield* ownConfigHome;
      yield* Effect.promise(async () => {
        await mkdir(nodePath.join(Credentials.path(), ".."), {
          recursive: true,
        });
        await writeFile(Credentials.path(), '{"url": "written by 0.23"}');
      });

      expect(yield* Credentials.list).toStrictEqual([]);
    })
  )
);
