import type { ResourceSummary } from "@clankerauth/admin-api";
import { Array, flow, pipe } from "effect";
import type { Html, HtmlBuilder } from "foldkit/html";
import {
  Button,
  EmptyState,
  PageHead,
  Panel,
  PropsList,
} from "@gjermundgaraba-designs/pixel-paper";

import { Change } from "./change.ts";
import { addResource, editResource } from "./form.ts";
import { Message } from "./message.ts";
import { codesView } from "../codes.ts";
import { type SectionContext, footView, itemButtonView, noteView } from "./parts.ts";

type ResourceView = typeof ResourceSummary.Type;

const BUILT_IN_NOTE =
  "Built-in administration resource, fixed. OAuth access tokens are required. clankerauth:read allows listing; clankerauth:write also allows every change.";

export const resourcesHeadView = (
  { listing, isHeld }: SectionContext,
  h: HtmlBuilder<Message>,
): Html =>
  PageHead.view(
    {
      title: "Resources",
      meta: `${listing.overview.resources.length}`,
      actions: [
        Button.view(
          {
            label: "add resource",
            glyph: "plus",
            isDisabled: isHeld,
            onClick: Message.ClickedOpenForm({ form: addResource() }),
          },
          h,
        ),
      ],
    },
    h,
  );

const connectedNames = ({ listing }: SectionContext, identifier: string): string => {
  const { clients, connections } = listing.overview;

  return pipe(
    clients,
    Array.filter(({ client_id }) =>
      Array.some(
        connections,
        (connection) => connection.client_id === client_id && connection.resource === identifier,
      ),
    ),
    Array.match({
      onEmpty: () => "None",
      onNonEmpty: flow(
        Array.map(({ client_id, client_name }) => client_name ?? client_id),
        Array.join(", "),
      ),
    }),
  );
};

const resourcePanel = (
  context: SectionContext,
  resource: ResourceView,
  h: HtmlBuilder<Message>,
): Html => {
  const { identifier, name, scopes, builtIn } = resource;

  return Panel.view(
    {
      id: `resource-${identifier}`,
      title: name,
      meta: builtIn ? "built in" : `${scopes.length} scopes`,
      body: [
        PropsList.view(
          {
            items: [
              { label: "identifier", value: [identifier], isCode: true },
              { label: "scopes", value: codesView(scopes, "None", h) },
              { label: "connected clients", value: [connectedNames(context, identifier)] },
            ],
          },
          h,
        ),
        ...(builtIn ? [noteView(BUILT_IN_NOTE, h)] : []),
      ],
      foot: footView(
        builtIn
          ? []
          : [
              itemButtonView(
                {
                  label: "edit",
                  itemName: name,
                  onClick: Message.ClickedOpenForm({ form: editResource(resource) }),
                  isHeld: context.isHeld,
                },
                h,
              ),
              itemButtonView(
                {
                  label: "delete",
                  itemName: name,
                  onClick: Message.ClickedChange({ change: Change.DeleteResource({ identifier }) }),
                  isHeld: context.isHeld,
                },
                h,
              ),
            ],
        h,
      ),
    },
    h,
  );
};

export const resourcesPanels = (
  context: SectionContext,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html> => [
  noteView("Protected APIs and MCP servers, and the scopes they define.", h),
  ...Array.match(context.listing.overview.resources, {
    onEmpty: () => [
      Panel.view(
        {
          id: "resources-empty",
          title: "Resources",
          meta: "0",
          body: [
            EmptyState.view(
              {
                title: "Add your first Resource",
                body: [
                  "Define a protected API or MCP server. Compatible MCP clients onboard automatically when you connect.",
                ],
              },
              h,
            ),
          ],
        },
        h,
      ),
    ],
    onNonEmpty: (resources) =>
      Array.map(resources, (resource) => resourcePanel(context, resource, h)),
  }),
];
