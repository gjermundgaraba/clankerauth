import type { Html, HtmlBuilder } from "foldkit/html";
import { Card, Wall, Wordmark } from "@gjermundgaraba-designs/pixel-paper";

export const PRODUCT = "clankerauth";

const markView = <Message>(h: HtmlBuilder<Message>): Html =>
  Wall.markView({ brand: [Wordmark.view({ label: PRODUCT }, h)] }, h);

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
