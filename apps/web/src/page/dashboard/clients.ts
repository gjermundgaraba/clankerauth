import {
  Button,
  Chip,
  EmptyState,
  PageHead,
  Panel,
  PropsList,
  Table,
} from "@gjermundgaraba-designs/pixel-paper";
import type { Client, Connection } from "@gjermundgaraba/clankerauth-admin-api";
import { Array, Option, pipe } from "effect";
import type { Html, HtmlBuilder } from "foldkit/html";

import { codesView } from "../codes.ts";
import { Change } from "./change.ts";
import { editAccess, editClient, registerClient } from "./form.ts";
import { Message } from "./message.ts";
import { footView, itemButtonView, momentOf, noteView } from "./parts.ts";
import type { SectionContext } from "./parts.ts";

type ClientView = typeof Client.Type;

type ConnectionView = typeof Connection.Type;

const INTRO =
  "Compatible MCP clients register themselves when they connect; registration alone grants no access. Revoking or blocking stops new authorization and refresh at once; already-issued access tokens stay valid until they expire, at most fifteen minutes.";

const ONBOARDING_LABELS = {
  managed: "Managed registration · first party, no consent screen",
  dcr: "Dynamic registration",
  cimd: "Client ID Metadata Document",
} as const;

const isManaged = ({ onboarding }: ClientView): boolean =>
  onboarding === undefined || onboarding === "managed";

const nameOf = ({ client_id, client_name }: ClientView): string =>
  client_name ?? client_id;

export const clientsHeadView = (
  { listing, isHeld }: SectionContext,
  h: HtmlBuilder<Message>
): Html =>
  PageHead.view(
    {
      title: "Clients",
      meta: `${listing.overview.clients.length}`,
      actions: [
        Button.view(
          {
            label: "register client",
            glyph: "plus",
            isDisabled: isHeld,
            onClick: Message.ClickedOpenForm({ form: registerClient() }),
          },
          h
        ),
      ],
    },
    h
  );

const historyOf = ({ approvedAt, refreshedAt }: ConnectionView): string =>
  Array.join(
    [
      Option.match(Option.fromNullishOr(approvedAt), {
        onNone: () => "First party, no consent",
        onSome: (moment) => `Approved ${momentOf(moment)}`,
      }),
      Option.match(Option.fromNullishOr(refreshedAt), {
        onNone: () => "no refresh token",
        onSome: (moment) => `last token ${momentOf(moment)}`,
      }),
    ],
    " · "
  );

const connectionsView = (
  context: SectionContext,
  client: ClientView,
  h: HtmlBuilder<Message>
): Html => {
  const { resources, connections } = context.listing.overview;

  const resourceName = (identifier: string): string =>
    Option.match(
      Array.findFirst(
        resources,
        (resource) => resource.identifier === identifier
      ),
      { onNone: () => identifier, onSome: ({ name }) => name }
    );

  return pipe(
    connections,
    Array.filter(({ client_id }) => client_id === client.client_id),
    Array.match({
      onEmpty: () =>
        noteView(
          isManaged(client)
            ? "Holds no refresh token."
            : "No Resource approved yet.",
          h
        ),
      onNonEmpty: (clientConnections) =>
        Table.view(
          {
            label: `Connections of ${nameOf(client)}`,
            rows: clientConnections,
            rowKey: ({ resource }) => resource,
            columns: [
              {
                key: "resource",
                header: "Resource",
                cell: ({ resource }) => [
                  resourceName(resource),
                  " ",
                  h.code([], [resource]),
                ],
              },
              {
                key: "scopes",
                header: "Scopes",
                cell: ({ scopes }) => [
                  Array.match(scopes, {
                    onEmpty: () => "No Resource scopes",
                    onNonEmpty: Array.join(" · "),
                  }),
                ],
              },
              {
                key: "history",
                header: "History",
                cell: (connection) => [historyOf(connection)],
              },
            ],
            actions: ({ resource }) => [
              Button.view(
                {
                  label: "revoke",
                  isSmall: true,
                  isDisabled: context.isHeld,
                  onClick: Message.ClickedChange({
                    change: Change.RevokeClient({
                      clientId: client.client_id,
                      maybeResource: Option.some(resource),
                    }),
                  }),
                  attributes: [h.AriaLabel(`Revoke ${resourceName(resource)}`)],
                },
                h
              ),
            ],
          },
          h
        ),
    })
  );
};

const change = (nextChange: Change): Message =>
  Message.ClickedChange({ change: nextChange });

const clientButtons = (
  context: SectionContext,
  client: ClientView,
  allowed: readonly string[],
  h: HtmlBuilder<Message>
): readonly Html[] => {
  const {
    client_id: clientId,
    blocked = false,
    token_endpoint_auth_method,
  } = client;

  const isConfidential = token_endpoint_auth_method !== "none";

  const smallButton = (label: string, onClick: Message): Html =>
    itemButtonView(
      { label, itemName: nameOf(client), onClick, isHeld: context.isHeld },
      h
    );

  return [
    ...(isManaged(client)
      ? [
          smallButton(
            "edit",
            Message.ClickedOpenForm({ form: editClient(client) })
          ),
          smallButton(
            "access",
            Message.ClickedOpenForm({ form: editAccess(client, allowed) })
          ),
        ]
      : []),
    ...(isManaged(client) && isConfidential
      ? [
          smallButton(
            "rotate secret",
            change(Change.RotateSecret({ clientId }))
          ),
        ]
      : []),
    smallButton(
      "revoke all",
      change(Change.RevokeClient({ clientId, maybeResource: Option.none() }))
    ),
    smallButton(
      blocked ? "unblock" : "block",
      change(Change.BlockClient({ clientId, isBlocked: !blocked }))
    ),
    smallButton(
      isManaged(client) ? "delete" : "forget",
      change(Change.DeleteClient({ clientId, isManaged: isManaged(client) }))
    ),
  ];
};

const clientPanel = (
  context: SectionContext,
  client: ClientView,
  h: HtmlBuilder<Message>
): Html => {
  const { resources, clientAccess } = context.listing.overview;

  const allowed = Array.flatMap(clientAccess, ({ client_id, resource }) =>
    client_id === client.client_id ? [resource] : []
  );

  return Panel.view(
    {
      id: `client-${client.client_id}`,
      title: client.client_name ?? "Unnamed client",
      meta:
        client.token_endpoint_auth_method === "none"
          ? "public · pkce"
          : "confidential · pkce",
      body: [
        PropsList.view(
          {
            items: [
              { label: "client id", value: [client.client_id], isCode: true },
              {
                label: "redirect uris",
                value: codesView(client.redirect_uris, "None", h),
              },
              {
                label: "registration",
                value: [ONBOARDING_LABELS[client.onboarding ?? "managed"]],
              },
              ...(client.blocked === true
                ? [
                    {
                      label: "status",
                      value: [
                        Chip.view({ label: "blocked", tone: "Blocked" }, h),
                      ],
                    },
                  ]
                : []),
              ...(isManaged(client)
                ? [
                    {
                      label: "allowed resources",
                      value: [`${allowed.length} of ${resources.length}`],
                    },
                  ]
                : []),
            ],
          },
          h
        ),
        connectionsView(context, client, h),
        noteView(
          isManaged(client)
            ? "Skips consent for its allowed Resources. Removing one revokes its authorization for it."
            : "May ask for any Resource; each needs your consent. Revoke a connection, or block the Client to keep it out.",
          h
        ),
      ],
      foot: footView(clientButtons(context, client, allowed, h), h),
    },
    h
  );
};

export const clientsPanels = (
  context: SectionContext,
  h: HtmlBuilder<Message>
): readonly Html[] => [
  noteView(INTRO, h),
  ...Array.match(context.listing.overview.clients, {
    onEmpty: () => [
      Panel.view(
        {
          id: "clients-empty",
          title: "Clients",
          meta: "0",
          body: [
            EmptyState.view(
              {
                title: "No Clients registered",
                headingLevel: 3,
                body: [
                  "Connect your MCP client to a configured server to onboard automatically, or register a managed Client here.",
                ],
              },
              h
            ),
          ],
        },
        h
      ),
    ],
    onNonEmpty: (clients) =>
      Array.map(clients, (client) => clientPanel(context, client, h)),
  }),
];
