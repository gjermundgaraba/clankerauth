#!/usr/bin/env node
import { Console, Effect, Option, type Schema } from "effect";
import { Argument, CliError, Command, Flag } from "effect/cli";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";
import { NodeRuntime, NodeServices } from "@effect/platform-node";
import * as ActionCli from "@gjermundgaraba/effect-actions/ActionCli";
import { Administration, OwnerHttp } from "@clankerauth/admin-api";
import manifest from "../package.json" with { type: "json" };
import { readCredentials, type CredentialsError } from "./credentials.ts";
import { accessToken, login, logout } from "./login.ts";
import type { OAuthError } from "./oauth.ts";

/** A failure of this CLI's own, rendered as its message on stderr, exiting 1. */
const refused = (error: OAuthError | CredentialsError) =>
  new CliError.UserError({ cause: error, userMessage: error.message });

const json = (value: Schema.Json) => Console.log(JSON.stringify(value, null, 2));

const loginCommand = Command.make(
  "login",
  {
    url: Argument.String("url").pipe(
      Argument.withDescription("The issuer's origin, such as https://auth.example.com"),
    ),
    readOnly: Flag.Boolean("read-only").pipe(
      Flag.withDescription("Ask for clankerauth:read alone: list, never change"),
      Flag.withDefault(false),
    ),
    browser: Flag.Boolean("browser").pipe(
      Flag.withDescription("Open the approval page; --no-browser only prints its URL"),
      Flag.withDefault(true),
    ),
  },
  ({ url, readOnly, browser }) =>
    login(url, readOnly, browser).pipe(Effect.mapError(refused), Effect.flatMap(json)),
).pipe(
  Command.withDescription(
    "Sign in to an issuer as its owner. The sign-in is kept in ~/.config/clankerauth.",
  ),
);

const logoutCommand = Command.make("logout", {}, () =>
  logout().pipe(Effect.mapError(refused), Effect.flatMap(json)),
).pipe(Command.withDescription("Revoke the sign-in and forget it."));

/**
 * The client every administration command calls through: the signed-in issuer's origin and
 * a current access token, refreshed and saved first when it has expired.
 */
const signedIn = Effect.gen(function* () {
  const stored = yield* readCredentials().pipe(Effect.mapError(refused));

  if (Option.isNone(stored))
    return yield* new CliError.UserError({
      cause: "not signed in",
      userMessage: "Not signed in: run `clankerauth login <url>` first.",
    });

  const { credentials, token } = yield* accessToken(stored.value).pipe(Effect.mapError(refused));

  return HttpClient.mapRequest(yield* HttpClient.HttpClient, (request) =>
    request.pipe(
      HttpClientRequest.prependUrl(credentials.url),
      HttpClientRequest.bearerToken(token),
    ),
  );
});

/** Every administration action, as a command of its own, called over `/api/owner`. */
const administration = Administration.map((action) =>
  ActionCli.remoteCommand(OwnerHttp, action).pipe(
    Command.provideEffect(HttpClient.HttpClient, signedIn),
  ),
);

const cli = Command.make("clankerauth").pipe(
  Command.withDescription(
    "Administer a clankerauth issuer as its owner. Results are JSON on stdout; a created key or client secret is in it once.",
  ),
  Command.withSubcommands([loginCommand, logoutCommand, ...administration]),
);

Command.run(cli, { version: manifest.version }).pipe(
  Effect.provide(FetchHttpClient.layer),
  Effect.provide(NodeServices.layer),
  ActionCli.logToStderr,
  NodeRuntime.runMain,
);
