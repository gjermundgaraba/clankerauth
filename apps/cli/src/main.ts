#!/usr/bin/env node
import { Console, Effect, Option, type Schema } from "effect";
import { Argument, CliError, Command, Flag } from "effect/cli";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";
import { NodeRuntime, NodeServices } from "@effect/platform-node";
import * as ActionCli from "@gjermundgaraba/effect-actions/ActionCli";
import { Administration, administrationIdentifier, OwnerHttp } from "@clankerauth/admin-api";
import manifest from "../package.json" with { type: "json" };
import { readCredentials, type CredentialsError } from "./credentials.ts";
import { accessToken, administrationScope, login, logout } from "./login.ts";
import type { OAuthError } from "./oauth.ts";

const refused = (error: OAuthError | CredentialsError) =>
  new CliError.UserError({ cause: error, userMessage: error.message });

const json = (value: Schema.Json) => Console.log(JSON.stringify(value, null, 2));

const resourceFlag = (description: string) =>
  Flag.String("resource").pipe(
    Flag.withDescription(description),
    Flag.mapTryCatch(
      (resource) => new URL(resource).href,
      () => "--resource must be a URL, such as https://notes.example/",
    ),
    Flag.optional,
  );

const scopeFor = Effect.fn("Cli.scopeFor")(function* (
  resource: Option.Option<string>,
  scope: Option.Option<string>,
) {
  if (Option.isSome(scope)) return scope.value;

  if (Option.isNone(resource)) return administrationScope;

  const message = `Name the scopes to ask ${resource.value} for with --scope.`;

  return yield* new CliError.UserError({ cause: message, userMessage: message });
});

const loginCommand = Command.make(
  "login",
  {
    url: Argument.String("url").pipe(
      Argument.withDescription("The issuer's origin, its CLANKERAUTH_BASE_URL"),
    ),
    resource: resourceFlag(
      "Sign in to this resource instead of administration, for `token` to use",
    ),
    scope: Flag.String("scope").pipe(
      Flag.withDescription(
        `The scopes to ask for, space-separated: needed with --resource, and "${administrationScope}" for administration by default`,
      ),
      Flag.optional,
    ),
  },
  ({ url, resource, scope }) =>
    scopeFor(resource, scope).pipe(
      Effect.flatMap((asked) => login(url, resource, asked).pipe(Effect.mapError(refused))),
      Effect.flatMap(json),
    ),
).pipe(
  Command.withDescription(
    "Sign in to an issuer as its owner, for administration or, with --resource, for another resource: approve the URL it prints in the browser. Sign-ins are kept in ~/.config/clankerauth.",
  ),
);

const logoutCommand = Command.make(
  "logout",
  { resource: resourceFlag("Sign out of this resource alone") },
  ({ resource }) => logout(resource).pipe(Effect.mapError(refused), Effect.flatMap(json)),
).pipe(Command.withDescription("Revoke the sign-ins, or the one to --resource, and forget them."));

const signedIn = Effect.gen(function* () {
  const stored = yield* readCredentials().pipe(Effect.mapError(refused));

  if (Option.isNone(stored))
    return yield* new CliError.UserError({
      cause: "not signed in",
      userMessage: "Not signed in: run `clankerauth login <url>` first.",
    });

  return stored.value;
});

const tokenCommand = Command.make(
  "token",
  { resource: resourceFlag("The resource whose token to print; administration by default") },
  ({ resource }) =>
    Effect.gen(function* () {
      const credentials = yield* signedIn;

      const token = yield* accessToken(
        credentials,
        Option.getOrElse(resource, () => administrationIdentifier(credentials.url)),
      ).pipe(Effect.mapError(refused));

      yield* Effect.sync(() => process.stdout.write(`${token}\n`));
    }),
).pipe(
  Command.withDescription(
    "Print a current access token for a resource signed in to, refreshing it first when it has expired.",
  ),
);

const administrationClient = Effect.gen(function* () {
  const credentials = yield* signedIn;

  const token = yield* accessToken(credentials, administrationIdentifier(credentials.url)).pipe(
    Effect.mapError(refused),
  );

  return HttpClient.mapRequest(yield* HttpClient.HttpClient, (request) =>
    request.pipe(
      HttpClientRequest.prependUrl(credentials.url),
      HttpClientRequest.bearerToken(token),
    ),
  );
});

const administration = Administration.map((action) =>
  ActionCli.remoteCommand(OwnerHttp, action).pipe(
    Command.provideEffect(HttpClient.HttpClient, administrationClient),
  ),
);

const cli = Command.make("clankerauth").pipe(
  Command.withDescription(
    "Administer a clankerauth issuer as its owner, and hand other commands its tokens. Results are JSON on stdout; a created key or client secret is in it once.",
  ),
  Command.withSubcommands([loginCommand, logoutCommand, tokenCommand, ...administration]),
);

Command.run(cli, { version: manifest.version }).pipe(
  Effect.provide(FetchHttpClient.layer),
  Effect.provide(NodeServices.layer),
  ActionCli.logToStderr,
  NodeRuntime.runMain,
);
