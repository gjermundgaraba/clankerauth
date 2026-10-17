import { ClientAuthMethod, type ResourceSummary } from "@gjermundgaraba/clankerauth-admin-api";
import { Array, Option, Record, Schema } from "effect";
import type { Html, HtmlBuilder } from "foldkit/html";
import { defineView } from "foldkit/submodel";
import {
  Choice,
  type Dialog,
  Field,
  Fieldset,
  PropsList,
  Rows,
  SelectField,
  Stack,
  TextareaField,
} from "@gjermundgaraba-designs/pixel-paper";

import { ClientMode, KeyMode, Message, Model, ResourceMode } from "./form.ts";
import { noteView } from "./parts.ts";

type ResourceView = typeof ResourceSummary.Type;

type ResourceForm = typeof Model.Resource.Type;

type KeyForm = typeof Model.Key.Type;

type ClientForm = typeof Model.Client.Type;

/** What the open form needs from the dashboard: what may be granted, and the attributes of the
 *  control that takes focus when the dialog opens. */
export type ViewInputs = Readonly<{
  resources: ReadonlyArray<ResourceView>;
  initialFocus: Dialog.RenderInfo["initialFocus"];
}>;

// WORDS

type FormLabels = Readonly<{ title: string; submit: string }>;

export const labelsOf = (form: Model): FormLabels =>
  Model.match(form, {
    Resource: ({ mode }) =>
      ResourceMode.match(mode, {
        Add: () => ({ title: "Add resource", submit: "add resource" }),
        Edit: () => ({ title: "Edit resource", submit: "save resource" }),
      }),
    Key: ({ mode }) =>
      KeyMode.match(mode, {
        Create: () => ({ title: "Create API key", submit: "create key" }),
        Rename: () => ({ title: "Rename key", submit: "save name" }),
        Grants: () => ({ title: "Edit grants", submit: "save grants" }),
      }),
    Client: ({ mode }) =>
      ClientMode.match(mode, {
        Register: () => ({ title: "Register client", submit: "register client" }),
        Edit: () => ({ title: "Edit client", submit: "save client" }),
        Access: () => ({ title: "Allowed resources", submit: "save access" }),
      }),
  });

const AUTH_METHOD_LABELS: Readonly<Record<typeof ClientAuthMethod.Type, string>> = {
  none: "Public client (PKCE only)",
  client_secret_basic: "Confidential client · HTTP Basic secret",
  client_secret_post: "Confidential client · secret in request body",
};

const SCOPE_HELP = "Optional. Separate scopes with spaces. offline_access is reserved.";

const REDIRECT_URI_ROWS = 3;

// FIELDS

const nameField = (
  config: Readonly<{ value: string; onInput: (value: string) => Message; label: string }>,
  inputs: ViewInputs,
  h: HtmlBuilder<Message>,
): Html =>
  Field.view(
    {
      id: "form-name",
      label: config.label,
      value: config.value,
      onInput: config.onInput,
      isRequired: true,
      inputAttributes: inputs.initialFocus,
    },
    h,
  );

const resourceFields = (
  { mode, draft }: ResourceForm,
  inputs: ViewInputs,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html> => {
  const isAdding = ResourceMode.guards.Add(mode);

  return [
    nameField(
      {
        label: "Name",
        value: draft.name,
        onInput: (value) => Message.UpdatedResourceName({ value }),
      },
      inputs,
      h,
    ),
    isAdding
      ? Field.view(
          {
            id: "form-identifier",
            label: "HTTP or HTTPS identifier",
            type: "url",
            value: draft.identifier,
            onInput: (value) => Message.UpdatedResourceIdentifier({ value }),
            isRequired: true,
            isMono: true,
            help: "The identifier is the token audience and cannot be changed later. Use the canonical form a client sends back, such as the application’s origin root with its trailing slash.",
            inputAttributes: [h.Placeholder("https://notes.internal/")],
          },
          h,
        )
      : PropsList.view(
          { items: [{ label: "identifier", value: [draft.identifier], isCode: true }] },
          h,
        ),
    Field.view(
      {
        id: "form-scopes",
        label: "Scopes",
        value: draft.scopes,
        onInput: (value) => Message.UpdatedResourceScopes({ value }),
        isMono: true,
        help: isAdding
          ? SCOPE_HELP
          : "Added scopes need new consent. Removed scopes are no longer issued, but approvals are kept and work again if the scope is restored.",
        inputAttributes: [h.Placeholder("notes:read notes:write")],
      },
      h,
    ),
  ];
};

const grantsView = (
  grants: KeyForm["draft"]["grants"],
  resources: ReadonlyArray<ResourceView>,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html> =>
  Array.match(resources, {
    onEmpty: () => [noteView("Add a Resource to grant access.", h)],
    onNonEmpty: (grantable) =>
      Array.map(grantable, ({ identifier, name, scopes }) =>
        Fieldset.view(
          {
            id: `form-grants-${identifier}`,
            label: name,
            body: [
              h.code([], [identifier]),
              Rows.view(
                {
                  label: `Scopes of ${name}`,
                  rows: Array.map(scopes, (scope) =>
                    Rows.rowView(
                      {
                        key: scope,
                        body: [h.code([], [scope])],
                        select: {
                          id: `form-grant-${identifier}-${scope}`,
                          isChecked: Option.exists(Record.get(grants, identifier), (granted) =>
                            Array.contains(granted, scope),
                          ),
                          onToggle: (isChecked) =>
                            Message.ToggledKeyGrant({ resource: identifier, scope, isChecked }),
                        },
                      },
                      h,
                    ),
                  ),
                },
                h,
              ),
            ],
          },
          h,
        ),
      ),
  });

const keyFields = (
  { mode, draft }: KeyForm,
  inputs: ViewInputs,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html> => {
  const name = nameField(
    { label: "Name", value: draft.name, onInput: (value) => Message.UpdatedKeyName({ value }) },
    inputs,
    h,
  );

  return KeyMode.match(mode, {
    Create: () => [
      name,
      ...grantsView(draft.grants, inputs.resources, h),
      Field.view(
        {
          id: "form-expiry",
          label: "Expiry (optional)",
          type: "datetime-local",
          value: draft.expiry,
          onInput: (value) => Message.UpdatedKeyExpiry({ value }),
          help: "Blank means valid until revoked. The key is shown once and works within about a minute.",
        },
        h,
      ),
    ],
    Rename: () => [name],
    Grants: () => [
      ...grantsView(draft.grants, inputs.resources, h),
      noteView(
        "Saving replaces all grants, including any not currently available, with the selected scopes.",
        h,
      ),
    ],
  });
};

const resourceChoicesView = (
  selected: ReadonlyArray<string>,
  resources: ReadonlyArray<ResourceView>,
  h: HtmlBuilder<Message>,
): Html =>
  Array.match(resources, {
    onEmpty: () => noteView("There are no Resources yet; add one to give this Client access.", h),
    onNonEmpty: (choices) =>
      Fieldset.view(
        {
          id: "form-resources",
          label: "Allowed resources",
          body: [
            Rows.view(
              {
                label: "Allowed resources",
                rows: Array.map(choices, ({ identifier, name }) =>
                  Rows.rowView(
                    {
                      key: identifier,
                      body: [name, " ", h.code([], [identifier])],
                      select: {
                        id: `form-resource-${identifier}`,
                        isChecked: Array.contains(selected, identifier),
                        onToggle: (isChecked) =>
                          Message.ToggledClientResource({ resource: identifier, isChecked }),
                      },
                    },
                    h,
                  ),
                ),
              },
              h,
            ),
          ],
        },
        h,
      ),
  });

const redirectUrisField = (value: string, h: HtmlBuilder<Message>): Html =>
  TextareaField.view(
    {
      id: "form-redirect-uris",
      label: "Redirect URIs",
      value,
      onInput: (nextValue) => Message.UpdatedClientRedirectUris({ value: nextValue }),
      help: "One per line.",
      isRequired: true,
      isMono: true,
      rows: REDIRECT_URI_ROWS,
      textareaAttributes: [h.Placeholder("https://app.internal/callback"), h.Spellcheck(false)],
    },
    h,
  );

const decodeAuthMethod = Schema.decodeUnknownOption(ClientAuthMethod);

const authMethodField = (method: typeof ClientAuthMethod.Type, h: HtmlBuilder<Message>): Html =>
  SelectField.view(
    {
      id: "form-auth-method",
      label: "Client authentication",
      value: method,
      onChange: (value) =>
        Message.SelectedClientAuthMethod({
          method: Option.getOrElse(decodeAuthMethod(value), () => method),
        }),
      options: Array.map(ClientAuthMethod.literals, (literal) => ({
        value: literal,
        label: AUTH_METHOD_LABELS[literal],
      })),
      help: "S256 PKCE is always required. It cannot be changed after registration.",
    },
    h,
  );

const nativeChoice = (isNative: boolean, h: HtmlBuilder<Message>): Html =>
  Choice.view(
    {
      id: "form-native",
      label: "Native or desktop client",
      note: "Its redirect is a loopback address on the device.",
      isChecked: isNative,
      onToggle: (isChecked) => Message.ToggledClientNative({ isChecked }),
    },
    h,
  );

const clientFields = (
  { mode, draft }: ClientForm,
  inputs: ViewInputs,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html> => {
  const name = nameField(
    {
      label: "Client name",
      value: draft.name,
      onInput: (value) => Message.UpdatedClientName({ value }),
    },
    inputs,
    h,
  );

  return ClientMode.match(mode, {
    Register: () => [
      name,
      redirectUrisField(draft.redirectUris, h),
      resourceChoicesView(draft.resources, inputs.resources, h),
      nativeChoice(draft.isNative, h),
      authMethodField(draft.authMethod, h),
      noteView("Clients you register here are first party and skip the consent screen.", h),
    ],
    Edit: () => [
      name,
      redirectUrisField(draft.redirectUris, h),
      nativeChoice(draft.isNative, h),
      noteView("The authentication method is fixed at registration.", h),
    ],
    Access: () => [
      resourceChoicesView(draft.resources, inputs.resources, h),
      noteView(
        "This Client skips consent for the Resources ticked here. Unticking one revokes its authorization for it.",
        h,
      ),
    ],
  });
};

// VIEW

export const view = defineView<Model, Message, ViewInputs>((form, inputs, h): Html =>
  Stack.view(
    {
      body: Model.match(form, {
        Resource: (resourceForm) => resourceFields(resourceForm, inputs, h),
        Key: (keyForm) => keyFields(keyForm, inputs, h),
        Client: (clientForm) => clientFields(clientForm, inputs, h),
      }),
    },
    h,
  ),
);
