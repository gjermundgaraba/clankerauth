import type { MachineKey, ResourceSummary } from "@clankerauth/admin-api";
import { Array, Option, Record } from "effect";
import type { Html, HtmlBuilder } from "foldkit/html";
import {
  Button,
  Chip,
  EmptyState,
  PageHead,
  Panel,
  PropsList,
} from "@gjermundgaraba-designs/pixel-paper";

import { Change } from "./change.ts";
import { createKey, editGrants, renameKey } from "./form.ts";
import { Message } from "./message.ts";
import { type SectionContext, footView, itemButtonView, momentOf, noteView } from "./parts.ts";

type KeyView = typeof MachineKey.Type;

type ResourceView = typeof ResourceSummary.Type;

const INTRO =
  "Direct access for CLIs and automation. Keys carry only the scopes you select, filtered by current Resource policy. Policy changes do not revoke stored grants; restoring policy restores access. Resource servers verify keys offline: a new key works within seconds and a key's expiry applies at once; any other change takes effect within about a minute, and a Resource server that cannot reach this issuer keeps accepting the keys it last saw for up to 24 hours.";

/** API keys can be granted on any Resource but the issuer's own administration. */
export const grantableResources = ({ listing }: SectionContext): ReadonlyArray<ResourceView> =>
  Array.filter(listing.overview.resources, ({ builtIn }) => !builtIn);

export const keysHeadView = (context: SectionContext, h: HtmlBuilder<Message>): Html =>
  PageHead.view(
    {
      title: "API keys",
      meta: `${context.listing.keys.length}`,
      actions: [
        Button.view(
          {
            label: "create key",
            glyph: "plus",
            isDisabled:
              context.isHeld || !Array.isReadonlyArrayNonEmpty(grantableResources(context)),
            onClick: Message.ClickedOpenForm({ form: createKey() }),
          },
          h,
        ),
      ],
    },
    h,
  );

const grantsView = (key: KeyView, h: HtmlBuilder<Message>): ReadonlyArray<Html | string> =>
  Array.match(Record.toEntries(key.permissions), {
    onEmpty: () => ["None"],
    onNonEmpty: (grants) =>
      Array.intersperse(
        Array.map(grants, ([resource, scopes]) =>
          h.span([], [h.code([], [resource]), " ", Array.join(scopes, " · ")]),
        ),
        h.br([]),
      ),
  });

const keyPanel = (context: SectionContext, key: KeyView, h: HtmlBuilder<Message>): Html => {
  const { keyId, name, enabled, expiresAt, createdAt } = key;

  const smallButton = (label: string, onClick: Message): Html =>
    itemButtonView({ label, itemName: name, onClick, isHeld: context.isHeld }, h);

  return Panel.view(
    {
      id: `key-${keyId}`,
      title: name,
      meta: enabled ? "enabled" : "disabled",
      body: [
        PropsList.view(
          {
            items: [
              {
                label: "state",
                value: [
                  enabled
                    ? Chip.view({ label: "enabled", tone: "Go" }, h)
                    : Chip.view({ label: "disabled" }, h),
                ],
              },
              {
                label: "expires",
                value: [
                  Option.match(Option.fromNullishOr(expiresAt), {
                    onNone: () => "Valid until revoked",
                    onSome: momentOf,
                  }),
                ],
              },
              { label: "created", value: [momentOf(createdAt)] },
              { label: "grants", value: grantsView(key, h) },
            ],
          },
          h,
        ),
      ],
      foot: footView(
        [
          smallButton("rename", Message.ClickedOpenForm({ form: renameKey(key) })),
          smallButton(
            "edit grants",
            Message.ClickedOpenForm({ form: editGrants(key, grantableResources(context)) }),
          ),
          smallButton(
            enabled ? "disable" : "enable",
            Message.ClickedChange({ change: Change.SetKeyEnabled({ keyId, isEnabled: !enabled }) }),
          ),
          smallButton(
            "delete",
            Message.ClickedChange({ change: Change.DeleteKey({ keyId, name }) }),
          ),
        ],
        h,
      ),
    },
    h,
  );
};

export const keysPanels = (
  context: SectionContext,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html> => [
  noteView(INTRO, h),
  ...Array.match(grantableResources(context), {
    onEmpty: () => [noteView("Add a Resource to grant access.", h)],
    onNonEmpty: () => [],
  }),
  ...Array.match(context.listing.keys, {
    onEmpty: () => [
      Panel.view(
        {
          id: "keys-empty",
          title: "API keys",
          meta: "0",
          body: [
            EmptyState.view(
              {
                title: "No API keys",
                body: ["Create a key for a CLI or automation that needs direct access."],
              },
              h,
            ),
          ],
        },
        h,
      ),
    ],
    onNonEmpty: (keys) => Array.map(keys, (key) => keyPanel(context, key, h)),
  }),
];
