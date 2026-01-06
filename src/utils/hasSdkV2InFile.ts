import { parse } from "oxc-parser";

const isAwsSdkV2 = (path: string) => path === "aws-sdk" || path.startsWith("aws-sdk/");

type AstNode = Record<string, unknown>;

const hasAwsSdkV2InRequire = (node: unknown): boolean => {
  if (!node || typeof node !== "object") return false;

  const n = node as AstNode;
  if (
    n.type === "CallExpression" &&
    (n.callee as AstNode)?.name === "require" &&
    isAwsSdkV2(((n.arguments as AstNode[])?.[0] as AstNode)?.value as string)
  ) {
    return true;
  }

  return Object.values(n).some((child) =>
    Array.isArray(child) ? child.some(hasAwsSdkV2InRequire) : hasAwsSdkV2InRequire(child),
  );
};

export const hasSdkV2InFile = async (filePath: string, fileContent: string) => {
  const { module, program } = await parse(filePath, fileContent);

  for (const { moduleRequest } of module.staticImports) {
    if (isAwsSdkV2(moduleRequest.value)) return true;
  }

  for (const { moduleRequest } of module.dynamicImports) {
    const importPath = fileContent.slice(moduleRequest.start + 1, moduleRequest.end - 1);
    if (isAwsSdkV2(importPath)) return true;
  }

  if (hasAwsSdkV2InRequire(program)) return true;

  return false;
};
