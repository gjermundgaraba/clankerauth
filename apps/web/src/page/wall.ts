import { Card, Wall, Wordmark } from "@gjermundgaraba-designs/pixel-paper";
import type { Html, HtmlBuilder } from "foldkit/html";

export const PRODUCT = "clankerauth";

const markView = <Message>(h: HtmlBuilder<Message>): Html =>
  Wall.markView({ brand: [Wordmark.view({ label: PRODUCT }, h)] }, h);

const wallView = <Message>(
  heading: string,
  card: Html,
  h: HtmlBuilder<Message>
): Html =>
  Wall.view({ body: [h.h1([h.Class("sr-only")], [heading]), card] }, h);

export const wallCardView = <Message>(
  heading: string,
  card: Card.ViewConfig<Message>,
  h: HtmlBuilder<Message>
): Html =>
  wallView(
    heading,
    Card.view(
      { isNarrow: true, ...card, body: [markView(h), ...card.body] },
      h
    ),
    h
  );

export const wallFormView = <Message>(
  heading: string,
  card: Card.FormViewConfig<Message>,
  h: HtmlBuilder<Message>
): Html =>
  wallView(
    heading,
    Card.formView(
      { isNarrow: true, ...card, body: [markView(h), ...card.body] },
      h
    ),
    h
  );
