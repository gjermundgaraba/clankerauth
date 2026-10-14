import { ApplicationType, ClientAuthMethod, KeyPermissions } from "@clankerauth/admin-api";
import { Array, Option, Schema, String, pipe } from "effect";
import { defineTaggedUnion } from "foldkit/schema";

// CHANGE

/** Every write the dashboard makes, each carrying what the issuer needs and what the owner is
 *  told about it. */
export const Change = defineTaggedUnion({
  CreateResource: {
    identifier: Schema.String,
    name: Schema.String,
    scopes: Schema.Array(Schema.String),
  },
  UpdateResource: {
    identifier: Schema.String,
    name: Schema.String,
    scopes: Schema.Array(Schema.String),
  },
  DeleteResource: { identifier: Schema.String },
  // A `datetime-local` value, or none for a key valid until revoked.
  CreateKey: {
    name: Schema.String,
    permissions: KeyPermissions,
    maybeExpiry: Schema.Option(Schema.String),
  },
  RenameKey: { keyId: Schema.String, name: Schema.String },
  SetKeyGrants: { keyId: Schema.String, permissions: KeyPermissions },
  SetKeyEnabled: { keyId: Schema.String, isEnabled: Schema.Boolean },
  DeleteKey: { keyId: Schema.String, name: Schema.String },
  RegisterClient: {
    name: Schema.String,
    redirectUris: Schema.Array(Schema.String),
    resources: Schema.Array(Schema.String),
    applicationType: ApplicationType,
    authMethod: ClientAuthMethod,
  },
  UpdateClient: {
    clientId: Schema.String,
    name: Schema.String,
    redirectUris: Schema.Array(Schema.String),
    applicationType: ApplicationType,
  },
  SetClientAccess: {
    clientId: Schema.String,
    resources: Schema.Array(Schema.String),
    removed: Schema.Array(Schema.String),
  },
  RevokeClient: { clientId: Schema.String, maybeResource: Schema.Option(Schema.String) },
  BlockClient: { clientId: Schema.String, isBlocked: Schema.Boolean },
  RotateSecret: { clientId: Schema.String },
  DeleteClient: { clientId: Schema.String, isManaged: Schema.Boolean },
});

export type Change = typeof Change.Type;

// CREDENTIAL

/** A secret the issuer shows once, which the owner must store before dismissing it. */
export const Credential = defineTaggedUnion({
  ClientSecret: { clientId: Schema.String, name: Schema.String, secret: Schema.String },
  ApiKey: { keyId: Schema.String, name: Schema.String, key: Schema.String },
});

export type Credential = typeof Credential.Type;

/** One id per thing a credential belongs to, so a rotated secret replaces the one before it. */
export const credentialId = (credential: Credential): string =>
  Credential.match(credential, {
    ClientSecret: ({ clientId }) => `client:${clientId}`,
    ApiKey: ({ keyId }) => `key:${keyId}`,
  });

/** Whether a credential stops meaning anything once this change is saved. */
export const isVoidedBy = (change: Change, credential: Credential): boolean =>
  Change.matchOrElse(
    change,
    {
      DeleteClient: ({ clientId }) => credentialId(credential) === `client:${clientId}`,
      DeleteKey: ({ keyId }) => credentialId(credential) === `key:${keyId}`,
    },
    () => false,
  );

/** A rotation changes nothing the dashboard lists, so only it is saved without a reread. */
export const needsReread = (change: Change): boolean => !Change.guards.RotateSecret(change);

// WORDS

/** What a ConfirmDialog asks before a change that revokes or destroys something. */
export type Confirmation = Readonly<{
  title: string;
  question: string;
  body: string;
  label: string;
  isDanger: boolean;
}>;

const REAUTHORIZE = "It must authorize again, and an automatic Client asks for consent.";

/** The question a change asks first, or none for a change that is saved at once. */
export const confirmationOf = (change: Change): Option.Option<Confirmation> =>
  Change.matchOrElse<Option.Option<Confirmation>>(
    change,
    {
      DeleteResource: ({ identifier }) =>
        Option.some({
          title: "Delete resource",
          question: "Delete this Resource?",
          body: `Every Client’s authorization for ${identifier} is revoked; API-key grants are kept.`,
          label: "delete",
          isDanger: true,
        }),
      DeleteKey: ({ name }) =>
        Option.some({
          title: "Delete API key",
          question: "Delete this API key?",
          body: `${name} stops working within about a minute. This cannot be undone.`,
          label: "delete",
          isDanger: true,
        }),
      SetClientAccess: ({ removed }) =>
        Array.match(removed, {
          onEmpty: () => Option.none(),
          onNonEmpty: (resources) =>
            Option.some({
              title: "Remove access",
              question: "Remove access?",
              body: `This revokes the Client’s authorization for ${Array.join(resources, ", ")}.`,
              label: "remove access",
              isDanger: true,
            }),
        }),
      RevokeClient: ({ maybeResource }) =>
        Option.some({
          title: "Revoke",
          question: Option.match(maybeResource, {
            onNone: () => "Revoke all of this Client’s authorization?",
            onSome: () => "Revoke this authorization?",
          }),
          body: Option.match(maybeResource, {
            onNone: () => REAUTHORIZE,
            onSome: (resource) =>
              `The Client loses its authorization for ${resource}. ${REAUTHORIZE}`,
          }),
          label: "revoke",
          isDanger: true,
        }),
      BlockClient: ({ isBlocked }) =>
        Option.some(
          isBlocked
            ? {
                title: "Block client",
                question: "Block this Client?",
                body: "Its authorization is revoked and it cannot authorize again until you unblock it.",
                label: "block",
                isDanger: true,
              }
            : {
                title: "Unblock client",
                question: "Unblock this Client?",
                body: "It may authorize again. Authorization revoked by the block stays revoked.",
                label: "unblock",
                isDanger: false,
              },
        ),
      RotateSecret: () =>
        Option.some({
          title: "Rotate secret",
          question: "Rotate the secret?",
          body: "The old one stops working immediately.",
          label: "rotate",
          isDanger: true,
        }),
      DeleteClient: ({ isManaged }) =>
        Option.some({
          title: isManaged ? "Delete client" : "Forget client",
          question: isManaged ? "Delete this Client?" : "Forget this Client?",
          body: isManaged
            ? "Its authorization is deleted with it."
            : "Its authorization is deleted with it. It can register again; block it to keep it out.",
          label: isManaged ? "delete" : "forget",
          isDanger: true,
        }),
    },
    () => Option.none(),
  );

/** What the page's live region says once a change is saved. */
export const announcementOf = (change: Change): string =>
  Change.match(change, {
    CreateResource: () => "Resource added.",
    UpdateResource: () => "Resource saved.",
    DeleteResource: () => "Resource deleted.",
    CreateKey: () => "API key created. Store it now.",
    RenameKey: () => "Key renamed.",
    SetKeyGrants: () => "Grants saved.",
    SetKeyEnabled: ({ isEnabled }) => (isEnabled ? "Key enabled." : "Key disabled."),
    DeleteKey: () => "Key deleted.",
    RegisterClient: () => "Client registered.",
    UpdateClient: () => "Client saved.",
    SetClientAccess: () => "Access saved.",
    RevokeClient: () => "Authorization revoked.",
    BlockClient: ({ isBlocked }) => (isBlocked ? "Client blocked." : "Client unblocked."),
    RotateSecret: () => "Secret rotated. Store it now.",
    DeleteClient: () => "Client deleted.",
  });

/** Splits what the owner typed into unique words: scopes, redirect URIs. */
export const splitWords = (text: string): ReadonlyArray<string> =>
  pipe(text.split(/\s+/u), Array.filter(String.isNonEmpty), Array.dedupe);
