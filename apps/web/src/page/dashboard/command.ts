import type { ClientCredentials } from "@gjermundgaraba/clankerauth-admin-api";
import { DateTime, Duration, Effect, Option } from "effect";
import { Command } from "foldkit";
import { load } from "foldkit/navigation";

import { issuer, signOut, toOwnerSentence } from "../../api.ts";
import { loginRouter } from "../../route.ts";
import { Change, Credential } from "./change.ts";
import { Message } from "./message.ts";

const clientSecretOf = (
  credentials: typeof ClientCredentials.Type
): Option.Option<Credential> =>
  Option.map(Option.fromNullishOr(credentials.client_secret), (secret) =>
    Credential.ClientSecret({
      clientId: credentials.client_id,
      name: credentials.client_name ?? credentials.client_id,
      secret,
    })
  );

const nothingShown = Effect.as(Option.none<Credential>());

const saveChange = (
  change: Change
): Effect.Effect<Option.Option<Credential>, string> =>
  toOwnerSentence<Option.Option<Credential>, unknown>(
    Change.match(change, {
      PutResource: ({ identifier, name, scopes }) =>
        issuer.putResource({ identifier, name, scopes }).pipe(nothingShown),
      DeleteResource: ({ identifier }) =>
        issuer.deleteResource({ identifier }).pipe(nothingShown),
      CreateKey: ({ name, permissions, maybeExpiry }) =>
        Effect.suspend(() =>
          issuer.createApiKey({
            name,
            permissions,
            expiresAt: Option.getOrNull(
              Option.map(maybeExpiry, (expiry) =>
                DateTime.fromDateUnsafe(new Date(expiry))
              )
            ),
          })
        ).pipe(
          Effect.map(({ keyId, name: keyName, key }) =>
            Option.some(Credential.ApiKey({ keyId, name: keyName, key }))
          )
        ),
      RenameKey: ({ keyId, name }) =>
        issuer.updateApiKey({ keyId, name }).pipe(nothingShown),
      SetKeyGrants: ({ keyId, permissions }) =>
        issuer.updateApiKey({ keyId, permissions }).pipe(nothingShown),
      SetKeyEnabled: ({ keyId, isEnabled }) =>
        issuer.updateApiKey({ keyId, enabled: isEnabled }).pipe(nothingShown),
      DeleteKey: ({ keyId }) =>
        issuer.deleteApiKey({ keyId }).pipe(nothingShown),
      RegisterClient: ({
        name,
        redirectUris,
        resources,
        applicationType,
        authMethod,
      }) =>
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
        issuer
          .setClientAccess({ client_id: clientId, resources })
          .pipe(nothingShown),
      RevokeClient: ({ clientId, maybeResource }) =>
        Option.match(maybeResource, {
          onNone: () => issuer.revokeClient({ client_id: clientId }),
          onSome: (resource) =>
            issuer.revokeClient({ client_id: clientId, resource }),
        }).pipe(nothingShown),
      BlockClient: ({ clientId, isBlocked }) =>
        issuer
          .blockClient({ client_id: clientId, blocked: isBlocked })
          .pipe(nothingShown),
      RotateSecret: ({ clientId }) =>
        issuer
          .rotateClientSecret({ client_id: clientId })
          .pipe(Effect.map(clientSecretOf)),
      DeleteClient: ({ clientId }) =>
        issuer.deleteClient({ client_id: clientId }).pipe(nothingShown),
    })
  );

const SAVE_TIMEOUT = Duration.seconds(20);

export const SaveChange = Command.define("SaveChange", {
  args: { change: Change },
  messages: [Message.SucceededSaveChange, Message.FailedSaveChange],
  execute: ({ change }) =>
    saveChange(change).pipe(
      Effect.match({
        onFailure: (reason) => Message.FailedSaveChange({ reason }),
        onSuccess: (maybeCredential) =>
          Message.SucceededSaveChange({ change, maybeCredential }),
      }),
      Effect.timeoutOrElse({
        duration: SAVE_TIMEOUT,
        orElse: () =>
          Effect.succeed(
            Message.FailedSaveChange({
              reason:
                "The issuer did not answer in time. Check whether the change was made before trying again.",
            })
          ),
      })
    ),
});

export const SignOut = Command.define("SignOut", {
  messages: [Message.SucceededSignOut, Message.FailedSignOut],
  execute: signOut.pipe(
    Effect.andThen(load(loginRouter())),
    Effect.match({
      onFailure: (reason) => Message.FailedSignOut({ reason }),
      onSuccess: () => Message.SucceededSignOut(),
    })
  ),
});
