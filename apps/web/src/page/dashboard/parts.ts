import { Button, Format, Wrap } from "@gjermundgaraba-designs/pixel-paper";
import { Array, DateTime } from "effect";
import type { Html, HtmlBuilder } from "foldkit/html";

import type { Listing } from "./listing.ts";

export type SectionContext = Readonly<{
  listing: Listing;
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

export const momentOf = (moment: DateTime.Utc): string =>
  MOMENT_FORMAT.format(DateTime.toDateUtc(moment));

export const noteView = <Message>(
  text: string,
  h: HtmlBuilder<Message>
): Html => h.p([h.Class("note-line")], [text]);

export const footView = <Message>(
  buttons: readonly Html[],
  h: HtmlBuilder<Message>
): readonly Html[] =>
  Array.match(buttons, {
    onEmpty: () => [],
    onNonEmpty: (body) => [h.span([h.Class("push")], [Wrap.view({ body }, h)])],
  });

export const itemButtonView = <Message>(
  config: Readonly<{
    label: string;
    itemName: string;
    onClick: Message;
    isHeld: boolean;
  }>,
  h: HtmlBuilder<Message>
): Html =>
  Button.view(
    {
      label: config.label,
      isSmall: true,
      isDisabled: config.isHeld,
      onClick: config.onClick,
      attributes: [h.AriaLabel(`${config.label} ${config.itemName}`)],
    },
    h
  );
