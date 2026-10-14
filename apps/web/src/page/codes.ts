import { Array } from "effect";
import type { Html, HtmlBuilder } from "foldkit/html";

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
