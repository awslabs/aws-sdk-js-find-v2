import { parse } from "oxc-parser";
import type { FileInfo } from "./constants.ts";

export const hasSdkV2InFile = async (fileInfo: FileInfo) => {
  const { module } = await parse(fileInfo.path, fileInfo.content);

  for (const { moduleRequest } of module.staticImports) {
    if (moduleRequest.value === "aws-sdk" || moduleRequest.value.startsWith("aws-sdk/")) {
      return true;
    }
  }

  for (const { moduleRequest } of module.dynamicImports) {
    const importPath = fileInfo.content.slice(moduleRequest.start + 1, moduleRequest.end - 1);
    if (importPath === "aws-sdk" || importPath.startsWith("aws-sdk/")) {
      return true;
    }
  }

  return false;
};
