import type { ClientCredentials } from "@clankerauth/admin-api";
import { DateTime, Effect, Option, Schema } from "effect";
import { Command } from "foldkit";
import { load } from "foldkit/navigation";
import { Announcer } from "@gjermundgaraba-designs/pixel-paper";

import { issuer, signOut, toOwnerSentence } from "../api.ts";
import { loginRouter } from "../route.ts";
import { Change, Credential } from "./change.ts";
import { Message } from "./message.ts";

// SAVE

const clientSecretOf = (credentials: typeof ClientCredentials.Type): Option.Option<Credential> =>
  Option.map(Option.fromNullishOr(credentials.client_secret), (secret) =>
    Credential.ClientSecret({
      clientId: credentials.client_id,
      name: credentials.client_name ?? credentials.client_id,
      secret,
    }),
  );

const nothingShown = Effect.as(Option.none<Credential>());

/** Saves a change at the issuer, with the credential it shows once, if any. */
const saveChange = (change: Change): Effect.Effect<Option.Option<Credential>, string> =>
  toOwnerSentence(
    Change.match(change, {
      CreateResource: ({ identifier, name, scopes }) =>
        issuer.createResource({ identifier, name, scopes }).pipe(nothingShown),
      UpdateResource: ({ identifier, name, scopes }) =>
        issuer.updateResource({ identifier, name, scopes }).pipe(nothingShown),
      DeleteResource: ({ identifier }) => issuer.deleteResource({ identifier }).pipe(nothingShown),
      // A `datetime-local` value has no zone, so the browser's own zone applies.
      CreateKey: ({ name, permissions, maybeExpiry }) =>
        Effect.suspend(() =>
          issuer.createApiKey({
            name,
            permissions,
            expiresAt: Option.getOrNull(
              Option.map(maybeExpiry, (expiry) => DateTime.fromDateUnsafe(new Date(expiry))),
            ),
          }),
        ).pipe(
          Effect.map(({ keyId, name: keyName, key }) =>
            Option.some(Credential.ApiKey({ keyId, name: keyName, key })),
          ),
        ),
      RenameKey: ({ keyId, name }) => issuer.updateApiKey({ keyId, name }).pipe(nothingShown),
      SetKeyGrants: ({ keyId, permissions }) =>
        issuer.updateApiKey({ keyId, permissions }).pipe(nothingShown),
      SetKeyEnabled: ({ keyId, isEnabled }) =>
        issuer.updateApiKey({ keyId, enabled: isEnabled }).pipe(nothingShown),
      DeleteKey: ({ keyId }) => issuer.deleteApiKey({ keyId }).pipe(nothingShown),
      RegisterClient: ({ name, redirectUris, resources, applicationType, authMethod }) =>
        issuer
          .createClient({
            client_name: name,
            redirect_uris: redirectUris,
            resources,
            application_type: applicationType,
            token_endpoint_auth_method: authMethod,
          })
          .pipe(Effect.map(clientSecretOf)),
      UpdateClient: ({ clientId, name, redirectUris, applicationType }) =>
        issuer
          .updateClient({
            client_id: clientId,
            client_name: name,
            redirect_uris: redirectUris,
            application_type: applicationType,
          })
          .pipe(nothingShown),
      SetClientAccess: ({ clientId, resources }) =>
        issuer.setClientAccess({ client_id: clientId, resources }).pipe(nothingShown),
      RevokeClient: ({ clientId, maybeResource }) =>
        Option.match(maybeResource, {
          onNone: () => issuer.revokeClient({ client_id: clientId }),
          onSome: (resource) => issuer.revokeClient({ client_id: clientId, resource }),
        }).pipe(nothingShown),
      BlockClient: ({ clientId, isBlocked }) =>
        issuer.blockClient({ client_id: clientId, blocked: isBlocked }).pipe(nothingShown),
      RotateSecret: ({ clientId }) =>
        issuer.rotateClientSecret({ client_id: clientId }).pipe(Effect.map(clientSecretOf)),
      DeleteClient: ({ clientId }) =>
        issuer.deleteClient({ client_id: clientId }).pipe(nothingShown),
    }),
  );

// COMMAND

export const FetchListing = Command.define("FetchListing", {
  messages: [Message.SettledFetchListing],
  execute: Effect.all(
    {
      overview: issuer.listClients(),
      keys: Effect.map(issuer.listApiKeys(), ({ keys }) => keys),
    },
    { concurrency: "unbounded" },
  ).pipe(
    toOwnerSentence,
    Effect.result,
    Effect.map((result) => Message.SettledFetchListing({ result })),
  ),
});

export const SaveChange = Command.define("SaveChange", {
  args: { change: Change },
  messages: [Message.SucceededSaveChange, Message.FailedSaveChange],
  execute: ({ change }) =>
    saveChange(change).pipe(
      Effect.match({
        onFailure: (reason) => Message.FailedSaveChange({ reason }),
        onSuccess: (maybeCredential) => Message.SucceededSaveChange({ change, maybeCredential }),
      }),
    ),
});

export const Announce = Command.define("Announce", {
  args: { text: Schema.String },
  messages: [Message.CompletedAnnounce],
  execute: ({ text }) => Announcer.announce(text).pipe(Effect.as(Message.CompletedAnnounce())),
});

export const SignOut = Command.define("SignOut", {
  messages: [Message.SucceededSignOut, Message.FailedSignOut],
  execute: signOut.pipe(
    Effect.andThen(load(loginRouter())),
    Effect.match({
      onFailure: (reason) => Message.FailedSignOut({ reason }),
      onSuccess: () => Message.SucceededSignOut(),
    }),
  ),
});
