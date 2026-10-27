import type { Options, Settings } from "vite-plus/lint/plugins";

type Json = Options[number];

const isObject = (value: Json | undefined): value is Settings =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isString = (value: Json): value is string => typeof value === "string";

/** The strings a rule's option object lists under `key`, if it lists any. */
export const optionList = (
  options: readonly Json[],
  key: string
): string[] | undefined => {
  const [first] = options;

  if (!isObject(first)) {
    return undefined;
  }

  const value = first[key];

  return Array.isArray(value) ? value.filter(isString) : undefined;
};
