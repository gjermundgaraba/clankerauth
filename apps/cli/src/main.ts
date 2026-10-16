#!/usr/bin/env node
import { Config, Console, Effect, Option, Redacted, type Schema } from "effect";
import { Argument, CliError, Command, Flag } from "effect/cli";
import { FetchHttpClient, HttpClient } from "effect/http";
import { NodeRuntime, NodeServices } from "@effect/platform-node";
import * as ActionCli from "@gjermundgaraba/effect-actions/ActionCli";
import * as ActionHttp from "@gjermundgaraba/effect-actions/ActionHttp";
import * as Credentials from "@gjermundgaraba/clankerauth-sdk/credentials";
import {
  Administration,
  administrationIdentifier,
  OwnerHttp,
} from "@gjermundgaraba/clankerauth-admin-api";
import manifest from "../package.json" with { type: "json" };

const refused = (error: { readonly message: string }) =>
  new CliError.UserError({ cause: error, userMessage: error.message });

const json = (value: Schema.Json) => Console.log(JSON.stringify(value, null, 2));

const urlArgument = (description: string) =>
  Argument.String("url").pipe(Argument.withDescription(description), Argument.optional);

const approve = (page: URL) =>
  Effect.sync(() =>
    process.stderr.write(
      `Open this URL in your browser to approve the sign-in:\n\n  ${page.href}\n\n`,
    ),
  );

const loginCommand = Command.make(
  "login",
  {
    url: Argument.String("url").pipe(
      Argument.withDescription(
        "The resource to sign in to: an application's URL, such as https://notes.example, or the issuer's origin, its CLANKERAUTH_BASE_URL, for administration",
      ),
    ),
    scope: Flag.String("scope").pipe(
      Flag.withDescription(
        "The scopes to ask for, space-separated: every scope the resource publishes by default",
      ),
      Flag.optional,
    ),
  },
  ({ url, scope }) =>
    Credentials.signIn(url, { scope: Option.getOrUndefined(scope), approve }).pipe(
      Effect.mapError(refused),
      Effect.flatMap(json),
    ),
).pipe(
  Command.withDescription(
    "Sign in as the issuer's owner to a resource: approve the URL it prints in the browser. The resource's issuer and scopes are read from its /.well-known/oauth-protected-resource. Sign-ins are kept in ~/.config/clankerauth, each beside the others, whatever its issuer.",
  ),
);

const logoutCommand = Command.make(
  "logout",
  { url: urlArgument("Sign out of the resource this URL is under alone") },
  ({ url }) =>
    Credentials.signOut(Option.getOrUndefined(url)).pipe(
      Effect.mapError(refused),
      Effect.flatMap(json),
    ),
).pipe(
  Command.withDescription(
    "Revoke the sign-ins, or the one to the resource a URL is under, and forget them.",
  ),
);

const notSignedIn = new CliError.UserError({
  cause: "not signed in",
  userMessage: "Not signed in: run `clankerauth login <url>` first.",
});

const administrationSignIn = Effect.gen(function* () {
  const named = yield* Config.option(Config.String("CLANKERAUTH_URL")).pipe(
    Effect.mapError(refused),
  );

  if (Option.exists(named, (url) => !URL.canParse(url)))
    return yield* new CliError.UserError({
      cause: "CLANKERAUTH_URL",
      userMessage:
        "CLANKERAUTH_URL is no URL: set it to the issuer's origin, its CLANKERAUTH_BASE_URL.",
    });

  const kept = (yield* Credentials.list().pipe(Effect.mapError(refused)))
    .filter((signIn) => signIn.resource === administrationIdentifier(signIn.url))
    .filter((signIn) =>
      Option.match(named, {
        onNone: () => true,
        onSome: (url) => new URL(url).origin === signIn.url,
      }),
    );

  const [only, ...others] = kept;

  if (only === undefined) return yield* notSignedIn;

  if (others.length > 0)
    return yield* new CliError.UserError({
      cause: "several issuers",
      userMessage: `Signed in to administration at ${kept.map((signIn) => signIn.url).join(", ")}: name one with CLANKERAUTH_URL.`,
    });

  return only;
});

const tokenCommand = Command.make(
  "token",
  {
    url: urlArgument(
      "An address under the resource whose token to print, such as the application's URL; administration by default",
    ),
  },
  ({ url }) =>
    Effect.gen(function* () {
      const named = Option.isSome(url) ? url.value : (yield* administrationSignIn).resource;

      const token = yield* Credentials.token({ url: named }).pipe(Effect.mapError(refused));

      yield* Effect.sync(() => process.stdout.write(`${Redacted.value(token)}\n`));
    }),
).pipe(
  Command.withDescription(
    "Print a current access token for the resource signed in to that a URL is under, refreshing it first when it has expired.",
  ),
);

const administrationClient = Effect.flatMap(administrationSignIn, (signIn) =>
  ActionHttp.client(OwnerHttp, {
    baseUrl: signIn.url,
    transformClient: (client) =>
      HttpClient.catchTag(
        Credentials.authorizing({ url: signIn.resource })(client),
        ["SignInRequired", "TokenUnavailable"],
        (error) => Effect.fail(refused(error)),
      ),
  }),
);

const administration = Administration.map((action) =>
  ActionCli.remoteCommand(OwnerHttp, action, { client: administrationClient }),
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
