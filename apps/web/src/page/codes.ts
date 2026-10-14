import { Array } from "effect";
import type { Html, HtmlBuilder } from "foldkit/html";

/** Identifiers as code, a space apart, or a word saying there are none. */
export const codesView = <Message>(
  values: ReadonlyArray<string>,
  none: string,
  h: HtmlBuilder<Message>,
): ReadonlyArray<Html | string> =>
  Array.match(values, {
    onEmpty: () => [none],
    onNonEmpty: (present) =>
      Array.intersperse(
        Array.map(present, (value) => h.code([], [value])),
        " ",
      ),
  });
