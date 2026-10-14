import { defineRule } from "vite-plus/lint/plugins";

import type { ESTree } from "vite-plus/lint/plugins";

type Options = { readonly allow?: ReadonlyArray<string> };

const runs = (object: string, property: string) =>
  object === "Effect"
    ? /^run[A-Z]/u.test(property)
    : object === "ManagedRuntime" ||
      ((object === "NodeRuntime" || object === "BunRuntime") && property === "runMain");

export const noManualEffectRunRule = defineRule({
  meta: {
    type: "problem",
    docs: {
      description:
        "Run Effects by hand only where a process starts or foreign code calls in; everywhere else they are composed and returned.",
    },
    messages: {
      manual:
        "`{{runner}}` runs an Effect by hand. Return the Effect, or run it in an entry or a bridge that the root vite.config.ts allows.",
    },
    schema: [
      {
        type: "object",
        properties: { allow: { type: "array", items: { type: "string" } } },
        additionalProperties: false,
      },
    ],
  },
  createOnce(context) {
    let allowed: ReadonlySet<string> = new Set();

    return {
      Program() {
        // SAFETY: oxlint checks the options against `meta.schema`.
        const options = (context.options[0] ?? {}) as Options;
        allowed = new Set(options.allow ?? []);
      },
      MemberExpression(node: ESTree.MemberExpression) {
        if (node.object.type !== "Identifier" || node.computed) return;

        if (node.property.type !== "Identifier") return;
        const property = node.property.name;

        if (!runs(node.object.name, property) || allowed.has(property)) return;
        context.report({
          node,
          messageId: "manual",
          data: { runner: `${node.object.name}.${property}` },
        });
      },
    };
  },
});
