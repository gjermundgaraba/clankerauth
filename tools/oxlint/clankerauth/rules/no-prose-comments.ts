import { defineRule } from "vite-plus/lint/plugins";

import type { ESTree } from "vite-plus/lint/plugins";

type Options = { readonly docBlocks: "types" | "all"; readonly sectionHeaders: boolean };

const typeDeclarations = new Set([
  "TSInterfaceDeclaration",
  "TSTypeAliasDeclaration",
  "TSPropertySignature",
  "TSMethodSignature",
  "TSIndexSignature",
  "TSCallSignatureDeclaration",
  "TSEnumDeclaration",
  "TSEnumMember",
  "TSModuleDeclaration",
]);

const rootName = (node: ESTree.Node): string | undefined => {
  let current = node;

  while (current.type === "CallExpression" || current.type === "MemberExpression")
    current = current.type === "CallExpression" ? current.callee : current.object;

  return current.type === "Identifier" ? current.name : undefined;
};

const isSchema = (node: ESTree.Node | null | undefined) =>
  node !== null && node !== undefined && rootName(node) === "Schema";

const declaresSchema = (node: ESTree.Node): boolean => {
  if (node.type === "VariableDeclaration")
    return node.declarations.some((declarator) => isSchema(declarator.init));

  if (node.type === "ClassDeclaration") return isSchema(node.superClass);

  if (node.type === "Property")
    return node.parent?.type === "ObjectExpression" && isSchema(node.parent.parent);

  return false;
};

const documentsType = (node: ESTree.Node): boolean =>
  typeDeclarations.has(node.type) ||
  declaresSchema(node) ||
  (node.type === "ExportNamedDeclaration" &&
    node.declaration !== null &&
    documentsType(node.declaration));

const directives = [
  /^\s*(?:eslint|oxlint)-(?:disable|enable)\S*(?:\s+[^-\s]\S*)*\s+--\s+\S/u,
  /^\s*@ts-expect-error\s+\S/u,
  /^\s*[#@]__PURE__\s*$/u,
  /^\/\s*<reference\s/u,
  /^\s*@vitest-environment\s+\S/u,
];

const marked = [/^ SAFETY: \S/u, /^ why: \S/u];

const sectionHeader = /^ [A-Z][A-Z0-9 ]*$/u;

export const noProseCommentsRule = defineRule({
  meta: {
    type: "suggestion",
    docs: {
      description:
        "Allow only tool directives with a reason, one-line `SAFETY:` and `why:` comments, documentation of types and schemas, and configured exceptions.",
    },
    messages: {
      prose:
        "Prose comment. Move its reason into a type, a name, a test or the commit message; keep a reason nothing else can carry as one `// why:` line.",
    },
    schema: [
      {
        type: "object",
        properties: {
          docBlocks: { enum: ["types", "all"] },
          sectionHeaders: { type: "boolean" },
        },
        additionalProperties: false,
      },
    ],
    defaultOptions: [{ docBlocks: "types", sectionHeaders: false }],
  },
  createOnce(context) {
    const documentsAType = (comment: ESTree.Comment): boolean => {
      const { text } = context.sourceCode;
      let offset = comment.end;

      while (offset < text.length && /\s/u.test(text.charAt(offset))) offset++;

      let node: ESTree.Node | null = context.sourceCode.getNodeByRangeIndex(offset);

      while (node !== null && node.start === offset) {
        if (documentsType(node)) return true;
        node = node.parent ?? null;
      }

      return false;
    };

    const allowed = (comment: ESTree.Comment, options: Options): boolean => {
      if (comment.start === 0 && context.sourceCode.text.startsWith("#!")) return true;

      if (directives.some((directive) => directive.test(comment.value))) return true;

      if (comment.type === "Line")
        return (
          marked.some((marker) => marker.test(comment.value)) ||
          (options.sectionHeaders && sectionHeader.test(comment.value))
        );

      if (!comment.value.startsWith("*")) return false;

      return options.docBlocks === "all" || documentsAType(comment);
    };

    return {
      Program() {
        // SAFETY: oxlint checks the options against `meta.schema` and fills in `defaultOptions`.
        const options = context.options[0] as Options;

        for (const comment of context.sourceCode.getAllComments()) {
          if (!allowed(comment, options)) context.report({ loc: comment.loc, messageId: "prose" });
        }
      },
    };
  },
});
