import StreamZip from "node-stream-zip";
import { AWS_SDK, NODE_MODULES, PACKAGE_JSON } from "./constants.ts";
import { join } from "node:path";

export interface LambdaFunctionContents {
  /**
   * Map with JS/TS filepath as key and contents as value.
   */
  codeMap: Map<string, string>;

  /**
   * Map with package.json filepath as key and contents as value.
   */
  packageJsonMap?: Map<string, string>;

  /**
   * Map with aws-sdk package.json filepath as key and contents as value.
   */
  awsSdkPackageJsonMap?: Map<string, string>;
}

/**
 * Extracts the contents of a Lambda Function zip file.
 *
 * Parses the zip and returns:
 * - JS/TS source files (excluding node_modules)
 * - package.json files (excluding node_modules)
 * - aws-sdk package.json from node_modules (for version detection)
 *
 * @param zipPath - The path to the zip file of Lambda Function.
 * @returns Extracted contents categorized by file type.
 */
export const getLambdaFunctionContents = async (
  zipPath: string,
): Promise<LambdaFunctionContents> => {
  const zip = new StreamZip.async({ file: zipPath });

  const codeMap = new Map<string, string>();
  const packageJsonMap = new Map<string, string>();
  const awsSdkPackageJsonMap = new Map<string, string>();

  let zipEntries: Record<string, StreamZip.ZipEntry> = {};
  try {
    zipEntries = await zip.entries();
  } catch {
    // Continue with empty object, if zip entries can't be read.
    // ToDo: add warning when logging is supported in future.
  }

  for (const zipEntry of Object.values(zipEntries)) {
    // Skip 'node_modules' directory, except for aws-sdk package.json file.
    if (zipEntry.name.includes(`${NODE_MODULES}/`)) {
      if (zipEntry.name.endsWith(join(NODE_MODULES, AWS_SDK, PACKAGE_JSON)) && zipEntry.isFile) {
        const packageJsonContent = await zip.entryData(zipEntry.name);
        awsSdkPackageJsonMap.set(zipEntry.name, packageJsonContent.toString());
      }
      continue;
    }

    // Skip if it is not a file
    if (!zipEntry.isFile) continue;

    // Populate 'package.json' files.
    if (zipEntry.name.endsWith(PACKAGE_JSON)) {
      try {
        const packageJsonContent = await zip.entryData(zipEntry.name);
        packageJsonMap.set(zipEntry.name, packageJsonContent.toString());
      } catch {
        // Continue without adding package.json file, if entry data can't be read.
        // ToDo: add warning when logging is supported in future.
      }
      continue;
    }

    // Populate JavaScript/TypeScript files.
    if (zipEntry.name.match(/\.(js|ts|mjs|cjs)$/)) {
      try {
        const codeContent = await zip.entryData(zipEntry.name);
        codeMap.set(zipEntry.name, codeContent.toString());
      } catch {
        // Continue without adding code, if entry data can't be read.
        // ToDo: add warning when logging is supported in future.
      }
      continue;
    }
  }

  await zip.close();
  return {
    codeMap,
    ...(packageJsonMap.size > 0 && { packageJsonMap }),
    ...(awsSdkPackageJsonMap.size > 0 && { awsSdkPackageJsonMap }),
  };
};
