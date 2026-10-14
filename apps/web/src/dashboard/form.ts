import {
  ClientAuthMethod,
  KeyPermissions,
  type Client,
  type MachineKey,
  type ResourceSummary,
} from "@clankerauth/admin-api";
import { Array, Option, Record, Result, Schema, String, pipe } from "effect";
import { defineMessageUnion } from "foldkit/message";
import { defineTaggedUnion } from "foldkit/schema";
import { modifyFields } from "foldkit/struct";

import { Change, splitWords } from "./change.ts";

// MODEL

const ResourceDraft = Schema.Struct({
  name: Schema.String,
  identifier: Schema.String,
  scopes: Schema.String,
});

type ResourceDraft = typeof ResourceDraft.Type;

const KeyDraft = Schema.Struct({
  name: Schema.String,
  grants: KeyPermissions,
  expiry: Schema.String,
});

type KeyDraft = typeof KeyDraft.Type;

const ClientDraft = Schema.Struct({
  name: Schema.String,
  redirectUris: Schema.String,
  resources: Schema.Array(Schema.String),
  isNative: Schema.Boolean,
  authMethod: ClientAuthMethod,
});

type ClientDraft = typeof ClientDraft.Type;

export const ResourceMode = defineTaggedUnion({ Add: {}, Edit: {} });

export const KeyMode = defineTaggedUnion({
  Create: {},
  Rename: { keyId: Schema.String },
  Grants: { keyId: Schema.String },
});

export const ClientMode = defineTaggedUnion({
  Register: {},
  Edit: { clientId: Schema.String },
  Access: { clientId: Schema.String, allowed: Schema.Array(Schema.String) },
});

/** The form in the dashboard's editor dialog: one kind of draft, in one of its modes. */
export const Model = defineTaggedUnion({
  Resource: { mode: ResourceMode, draft: ResourceDraft },
  Key: { mode: KeyMode, draft: KeyDraft },
  Client: { mode: ClientMode, draft: ClientDraft },
});

export type Model = typeof Model.Type;

type ResourceView = typeof ResourceSummary.Type;

type ClientView = typeof Client.Type;

type KeyView = typeof MachineKey.Type;

type Grants = typeof KeyPermissions.Type;

// MESSAGE

export const Message = defineMessageUnion({
  UpdatedResourceName: { value: Schema.String },
  UpdatedResourceIdentifier: { value: Schema.String },
  UpdatedResourceScopes: { value: Schema.String },
  UpdatedKeyName: { value: Schema.String },
  ToggledKeyGrant: { resource: Schema.String, scope: Schema.String, isChecked: Schema.Boolean },
  UpdatedKeyExpiry: { value: Schema.String },
  UpdatedClientName: { value: Schema.String },
  UpdatedClientRedirectUris: { value: Schema.String },
  ToggledClientResource: { resource: Schema.String, isChecked: Schema.Boolean },
  ToggledClientNative: { isChecked: Schema.Boolean },
  SelectedClientAuthMethod: { method: ClientAuthMethod },
});

export type Message = typeof Message.Type;

// OPEN

export const addResource = (): Model =>
  Model.Resource({ mode: ResourceMode.Add(), draft: { name: "", identifier: "", scopes: "" } });

export const editResource = ({ name, identifier, scopes }: ResourceView): Model =>
  Model.Resource({
    mode: ResourceMode.Edit(),
    draft: { name, identifier, scopes: Array.join(scopes, " ") },
  });

export const createKey = (): Model =>
  Model.Key({ mode: KeyMode.Create(), draft: { name: "", grants: {}, expiry: "" } });

export const renameKey = ({ keyId, name, permissions }: KeyView): Model =>
  Model.Key({ mode: KeyMode.Rename({ keyId }), draft: { name, grants: permissions, expiry: "" } });

const grantEntry = (
  resource: string,
  scopes: ReadonlyArray<string>,
): ReadonlyArray<readonly [string, ReadonlyArray<string>]> =>
  Array.isReadonlyArrayNonEmpty(scopes) ? [[resource, scopes]] : [];

/** Grants as they apply now: on a Resource that exists, for scopes it still defines. */
const grantsInForce = (permissions: Grants, resources: ReadonlyArray<ResourceView>): Grants =>
  Record.fromEntries(
    Array.flatMap(resources, ({ identifier, scopes }) =>
      grantEntry(
        identifier,
        Array.intersection(
          Option.getOrElse(Record.get(permissions, identifier), () => []),
          scopes,
        ),
      ),
    ),
  );

/** Saving replaces every grant with the scopes ticked, so one on a Resource or a scope that no
 *  longer exists goes. */
export const editGrants = (
  { keyId, name, permissions }: KeyView,
  resources: ReadonlyArray<ResourceView>,
): Model =>
  Model.Key({
    mode: KeyMode.Grants({ keyId }),
    draft: { name, expiry: "", grants: grantsInForce(permissions, resources) },
  });

const clientDraftOf = (client: ClientView, resources: ReadonlyArray<string>): ClientDraft => ({
  name: client.client_name ?? "",
  redirectUris: Array.join(client.redirect_uris, "\n"),
  resources,
  isNative: client.application_type === "native",
  authMethod: "none",
});

export const registerClient = (): Model =>
  Model.Client({
    mode: ClientMode.Register(),
    draft: { name: "", redirectUris: "", resources: [], isNative: false, authMethod: "none" },
  });

export const editClient = (client: ClientView): Model =>
  Model.Client({
    mode: ClientMode.Edit({ clientId: client.client_id }),
    draft: clientDraftOf(client, []),
  });

export const editAccess = (client: ClientView, allowed: ReadonlyArray<string>): Model =>
  Model.Client({
    mode: ClientMode.Access({ clientId: client.client_id, allowed }),
    draft: clientDraftOf(client, allowed),
  });

// UPDATE

/** Applies an edit to a Resource draft, and leaves any other form as it is. */
const editResourceDraft = (form: Model, edit: (draft: ResourceDraft) => ResourceDraft): Model =>
  Model.matchOrElse(
    form,
    { Resource: (resourceForm) => modifyFields(resourceForm, { draft: edit }) },
    () => form,
  );

/** Applies an edit to an API key draft, and leaves any other form as it is. */
const editKeyDraft = (form: Model, edit: (draft: KeyDraft) => KeyDraft): Model =>
  Model.matchOrElse(form, { Key: (keyForm) => modifyFields(keyForm, { draft: edit }) }, () => form);

/** Applies an edit to a Client draft, and leaves any other form as it is. */
const editClientDraft = (form: Model, edit: (draft: ClientDraft) => ClientDraft): Model =>
  Model.matchOrElse(
    form,
    { Client: (clientForm) => modifyFields(clientForm, { draft: edit }) },
    () => form,
  );

/** Ticks or unticks one value of a selection, keeping it once. */
const toggleValue =
  (value: string, isChecked: boolean) =>
  (values: ReadonlyArray<string>): ReadonlyArray<string> => {
    const others = Array.filter(values, (other) => other !== value);

    return isChecked ? Array.append(others, value) : others;
  };

/** Ticks or unticks one scope of one Resource; a Resource left with none is not granted. */
const toggleGrant =
  (resource: string, scope: string, isChecked: boolean) =>
  (grants: Grants): Grants => {
    const scopes = pipe(
      Record.get(grants, resource),
      Option.getOrElse((): ReadonlyArray<string> => []),
      toggleValue(scope, isChecked),
    );

    return Array.isReadonlyArrayNonEmpty(scopes)
      ? Record.set(grants, resource, scopes)
      : Record.remove(grants, resource);
  };

/** The form after one edit. Editing only ever changes the draft, so there is nothing else to
 *  return. */
export const update = (form: Model, message: Message): Model =>
  Message.match<Model>(message, {
    UpdatedResourceName: ({ value }) =>
      editResourceDraft(form, (draft) => modifyFields(draft, { name: () => value })),
    UpdatedResourceIdentifier: ({ value }) =>
      editResourceDraft(form, (draft) => modifyFields(draft, { identifier: () => value })),
    UpdatedResourceScopes: ({ value }) =>
      editResourceDraft(form, (draft) => modifyFields(draft, { scopes: () => value })),
    UpdatedKeyName: ({ value }) =>
      editKeyDraft(form, (draft) => modifyFields(draft, { name: () => value })),
    ToggledKeyGrant: ({ resource, scope, isChecked }) =>
      editKeyDraft(form, (draft) =>
        modifyFields(draft, { grants: toggleGrant(resource, scope, isChecked) }),
      ),
    UpdatedKeyExpiry: ({ value }) =>
      editKeyDraft(form, (draft) => modifyFields(draft, { expiry: () => value })),
    UpdatedClientName: ({ value }) =>
      editClientDraft(form, (draft) => modifyFields(draft, { name: () => value })),
    UpdatedClientRedirectUris: ({ value }) =>
      editClientDraft(form, (draft) => modifyFields(draft, { redirectUris: () => value })),
    ToggledClientResource: ({ resource, isChecked }) =>
      editClientDraft(form, (draft) =>
        modifyFields(draft, { resources: toggleValue(resource, isChecked) }),
      ),
    ToggledClientNative: ({ isChecked }) =>
      editClientDraft(form, (draft) => modifyFields(draft, { isNative: () => isChecked })),
    SelectedClientAuthMethod: ({ method }) =>
      editClientDraft(form, (draft) => modifyFields(draft, { authMethod: () => method })),
  });

// SUBMIT

const NO_REDIRECT = "Add at least one redirect URI.";

const INVALID_EXPIRY = "Enter the expiry as a date and time, or leave it blank.";

const redirectUrisOf = (draft: ClientDraft): Result.Result<ReadonlyArray<string>, string> =>
  Array.match(splitWords(draft.redirectUris), {
    onEmpty: () => Result.fail(NO_REDIRECT),
    onNonEmpty: Result.succeed,
  });

/** A blank expiry is a key valid until revoked; anything else must read as a moment. */
const expiryOf = (expiry: string): Result.Result<Option.Option<string>, string> =>
  pipe(
    Option.liftPredicate(expiry, String.isNonEmpty),
    Option.match({
      onNone: () => Result.succeed(Option.none()),
      onSome: (moment) =>
        Number.isNaN(Date.parse(moment))
          ? Result.fail(INVALID_EXPIRY)
          : Result.succeed(Option.some(moment)),
    }),
  );

const applicationTypeOf = (draft: ClientDraft) => (draft.isNative ? "native" : "web");

const resourceChangeOf = (mode: typeof ResourceMode.Type, draft: ResourceDraft): Change => {
  const fields = {
    identifier: draft.identifier.trim(),
    name: draft.name.trim(),
    scopes: splitWords(draft.scopes),
  };

  return ResourceMode.match(mode, {
    Add: () => Change.CreateResource(fields),
    Edit: () => Change.UpdateResource(fields),
  });
};

const keyChangeOf = (mode: typeof KeyMode.Type, draft: KeyDraft): Result.Result<Change, string> =>
  KeyMode.match(mode, {
    Create: () =>
      Result.map(expiryOf(draft.expiry), (maybeExpiry) =>
        Change.CreateKey({ name: draft.name.trim(), permissions: draft.grants, maybeExpiry }),
      ),
    Rename: ({ keyId }) => Result.succeed(Change.RenameKey({ keyId, name: draft.name.trim() })),
    Grants: ({ keyId }) =>
      Result.succeed(Change.SetKeyGrants({ keyId, permissions: draft.grants })),
  });

const clientChangeOf = (
  mode: typeof ClientMode.Type,
  draft: ClientDraft,
): Result.Result<Change, string> =>
  ClientMode.match(mode, {
    Register: () =>
      Result.map(redirectUrisOf(draft), (redirectUris) =>
        Change.RegisterClient({
          name: draft.name.trim(),
          redirectUris,
          resources: draft.resources,
          applicationType: applicationTypeOf(draft),
          authMethod: draft.authMethod,
        }),
      ),
    Edit: ({ clientId }) =>
      Result.map(redirectUrisOf(draft), (redirectUris) =>
        Change.UpdateClient({
          clientId,
          name: draft.name.trim(),
          redirectUris,
          applicationType: applicationTypeOf(draft),
        }),
      ),
    Access: ({ clientId, allowed }) =>
      Result.succeed(
        Change.SetClientAccess({
          clientId,
          resources: draft.resources,
          removed: Array.difference(allowed, draft.resources),
        }),
      ),
  });

/** The change a submitted form asks for, or why it cannot be sent. Every other rule is the
 *  contract's, which the issuer's client applies before anything is sent. */
export const changeOf = (form: Model): Result.Result<Change, string> =>
  Model.match(form, {
    Resource: ({ mode, draft }) => Result.succeed(resourceChangeOf(mode, draft)),
    Key: ({ mode, draft }) => keyChangeOf(mode, draft),
    Client: ({ mode, draft }) => clientChangeOf(mode, draft),
  });
