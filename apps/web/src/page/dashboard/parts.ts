import { Array, DateTime } from "effect";
import type { Html, HtmlBuilder } from "foldkit/html";
import { Button, Format, Wrap } from "@gjermundgaraba-designs/pixel-paper";

import type { Listing } from "./listing.ts";

/** What every section of the dashboard renders from. */
export type SectionContext = Readonly<{
  listing: Listing;
  /** Whether every change is held; see `isHeld`. */
  isHeld: boolean;
}>;

const MOMENT_FORMAT = new Intl.DateTimeFormat(Format.LOCALE, {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
});

/** A moment in the reader's zone, in English: `"12 Mar 2026, 14:05"`. */
export const momentOf = (moment: DateTime.Utc): string =>
  MOMENT_FORMAT.format(DateTime.toDateUtc(moment));

export const noteView = <Message>(text: string, h: HtmlBuilder<Message>): Html =>
  h.p([h.Class("note-line")], [text]);

/** A panel's foot of small buttons, pushed right; nothing when there are none. */
export const footView = <Message>(
  buttons: ReadonlyArray<Html>,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html> =>
  Array.match(buttons, {
    onEmpty: () => [],
    onNonEmpty: (body) => [h.span([h.Class("push")], [Wrap.view({ body }, h)])],
  });

/** A small button acting on one item of a section, named for the item as well, so a screen
 *  reader's list of buttons tells the items apart. Nothing is offered while changes are held. */
export const itemButtonView = <Message>(
  config: Readonly<{ label: string; itemName: string; onClick: Message; isHeld: boolean }>,
  h: HtmlBuilder<Message>,
): Html =>
  Button.view(
    {
      label: config.label,
      isSmall: true,
      isDisabled: config.isHeld,
      onClick: config.onClick,
      attributes: [h.AriaLabel(`${config.label} ${config.itemName}`)],
    },
    h,
  );
