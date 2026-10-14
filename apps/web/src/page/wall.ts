import type { Html, HtmlBuilder } from "foldkit/html";
import { Card, Wall, Wordmark } from "@gjermundgaraba-designs/pixel-paper";

/** The product's name, as its wordmark and page titles say it. */
export const PRODUCT = "clankerauth";

/** The product's mark at wall size, at the top of a wall's card. */
const markView = <Message>(h: HtmlBuilder<Message>): Html =>
  Wall.markView({ brand: [Wordmark.view({ label: PRODUCT }, h)] }, h);

/**
 * A page that is one card on the ground (sign-in, setup, consent), with the product's mark at
 * the top of the card. The card is narrow unless `card` says otherwise. The card's title is its
 * bar, so the page names itself with a heading for screen readers.
 */
export const wallCardView = <Message>(
  heading: string,
  card: Card.ViewConfig<Message>,
  h: HtmlBuilder<Message>,
): Html =>
  Wall.view(
    {
      body: [
        h.h1([h.Class("sr-only")], [heading]),
        Card.view({ isNarrow: true, ...card, body: [markView(h), ...card.body] }, h),
      ],
    },
    h,
  );
