import { parse } from "oxc-parser";
export const hasSdkV2InFile = async (filePath: string, fileContent: string) => {
  const { module } = await parse(filePath, fileContent);

  for (const { moduleRequest } of module.staticImports) {
    if (moduleRequest.value === "aws-sdk" || moduleRequest.value.startsWith("aws-sdk/")) {
      return true;
    }
  }

  for (const { moduleRequest } of module.dynamicImports) {
    const importPath = fileContent.slice(moduleRequest.start + 1, moduleRequest.end - 1);
    if (importPath === "aws-sdk" || importPath.startsWith("aws-sdk/")) {
      return true;
    }
  }

  return false;
};
