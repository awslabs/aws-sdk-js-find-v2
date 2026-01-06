import { parseSync } from "oxc-parser";

const isAwsSdkV2 = (path: string) => path === "aws-sdk" || path.startsWith("aws-sdk/");

type AstNode = Record<string, unknown>;

const hasAwsSdkV2InAst = (node: unknown): boolean => {
  if (!node || typeof node !== "object") return false;

  const n = node as AstNode;

  // Search for aws-sdk in require
  if (
    n.type === "CallExpression" &&
    (n.callee as AstNode)?.name === "require" &&
    isAwsSdkV2(((n.arguments as AstNode[])?.[0] as AstNode)?.value as string)
  ) {
    return true;
  }

  // Search for aws-sdk in import equals
  if (
    n.type === "TSImportEqualsDeclaration" &&
    (n.moduleReference as AstNode)?.type === "TSExternalModuleReference" &&
    isAwsSdkV2(((n.moduleReference as AstNode)?.expression as AstNode)?.value as string)
  ) {
    return true;
  }

  // Search for aws-sdk in dynamic import
  if (n.type === "ImportExpression" && isAwsSdkV2(((n.source as AstNode)?.value as string) ?? "")) {
    return true;
  }

  return Object.values(n).some((child) =>
    Array.isArray(child) ? child.some(hasAwsSdkV2InAst) : hasAwsSdkV2InAst(child),
  );
};

export const hasSdkV2InFile = (filePath: string, fileContent: string) => {
  const { module, program } = parseSync(filePath, fileContent);

  for (const { moduleRequest } of module.staticImports) {
    if (isAwsSdkV2(moduleRequest.value)) return true;
  }

  if (hasAwsSdkV2InAst(program)) return true;

  return false;
};
