import { defineRule } from "vite-plus/lint/plugins";
import type { ESTree } from "vite-plus/lint/plugins";

import { optionList } from "./options.ts";

const runs = (object: string, property: string) =>
  object === "Effect"
    ? /^run[A-Z]/u.test(property)
    : object === "ManagedRuntime" ||
      ((object === "NodeRuntime" || object === "BunRuntime") &&
        property === "runMain");

export const noManualEffectRunRule = defineRule({
  meta: {
    type: "problem",
    docs: {
      description:
        "Run Effects by hand only where a process starts or foreign code calls in; everywhere else they are composed and returned.",
    },
    messages: {
      manual:
        "`{{runner}}` runs an Effect by hand. Return the Effect, or run it in an entry or a bridge that the root oxlint.config.ts allows.",
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
        allowed = new Set(optionList(context.options, "allow"));
      },
      MemberExpression(node: ESTree.MemberExpression) {
        if (node.object.type !== "Identifier" || node.computed) {
          return;
        }

        if (node.property.type !== "Identifier") {
          return;
        }

        const property = node.property.name;

        if (!runs(node.object.name, property) || allowed.has(property)) {
          return;
        }

        context.report({
          node,
          messageId: "manual",
          data: { runner: `${node.object.name}.${property}` },
        });
      },
    };
  },
});
