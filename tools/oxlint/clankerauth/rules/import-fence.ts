import { defineRule } from "vite-plus/lint/plugins";

import type { ESTree } from "vite-plus/lint/plugins";

type Options = { readonly allow?: ReadonlyArray<string>; readonly deny?: ReadonlyArray<string> };

const isRelative = (specifier: string) => specifier.startsWith("./") || specifier.startsWith("../");

const isStringLiteral = (node: ESTree.Expression): node is ESTree.StringLiteral =>
  node.type === "Literal" && typeof node.value === "string";

const fromRoot = (root: string, filename: string, specifier: string) => {
  const path = filename.replaceAll("\\", "/").split("/").slice(0, -1);

  for (const segment of specifier.split("/")) {
    if (segment === "..") path.pop();
    else if (segment !== ".") path.push(segment);
  }

  const prefix = `${root.replaceAll("\\", "/")}/`;
  const absolute = path.join("/");

  return absolute.startsWith(prefix) ? absolute.slice(prefix.length) : absolute;
};

export const importFenceRule = defineRule({
  meta: {
    type: "problem",
    docs: {
      description:
        "Allow a folder only the imports its fence lists, and refuse those it denies. Relative imports are matched as paths from the repository root.",
    },
    messages: {
      fenced:
        "`{{specifier}}` is outside this folder's import fence. AGENTS.md records what each folder may import.",
      dynamic:
        "An import whose specifier is not a string literal cannot be checked against this folder's fence.",
    },
    schema: [
      {
        type: "object",
        properties: {
          allow: { type: "array", items: { type: "string" } },
          deny: { type: "array", items: { type: "string" } },
        },
        additionalProperties: false,
      },
    ],
  },
  createOnce(context) {
    let allow: ReadonlyArray<RegExp> | undefined;
    let deny: ReadonlyArray<RegExp> = [];

    const check = (node: ESTree.Node, specifier: string) => {
      const target = isRelative(specifier)
        ? fromRoot(context.cwd, context.filename, specifier)
        : specifier;

      const refused =
        (allow !== undefined && !allow.some((pattern) => pattern.test(target))) ||
        deny.some((pattern) => pattern.test(target));

      if (refused) context.report({ node, messageId: "fenced", data: { specifier } });
    };

    const fromSource = (node: { readonly source: ESTree.StringLiteral | null } & ESTree.Node) => {
      if (node.source !== null) check(node, node.source.value);
    };

    return {
      Program() {
        // SAFETY: oxlint checks the options against `meta.schema`.
        const options = (context.options[0] ?? {}) as Options;
        allow = options.allow?.map((pattern) => new RegExp(pattern, "u"));
        deny = (options.deny ?? []).map((pattern) => new RegExp(pattern, "u"));
      },
      ImportDeclaration: fromSource,
      ExportNamedDeclaration: fromSource,
      ExportAllDeclaration: fromSource,
      TSImportType: (node) => check(node, node.source.value),
      ImportExpression(node) {
        if (isStringLiteral(node.source)) check(node, node.source.value);
        else context.report({ node, messageId: "dynamic" });
      },
    };
  },
});
