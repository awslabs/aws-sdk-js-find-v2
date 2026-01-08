import { AWS_SDK_PACKAGE_JSON, NODE_MODULES, PACKAGE_JSON } from "./constants.ts";
import { processZipEntries } from "./processZipEntries.ts";

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
  const codeMap = new Map<string, string>();
  const packageJsonMap = new Map<string, string>();
  const awsSdkPackageJsonMap = new Map<string, string>();

  await processZipEntries(zipPath, async (entry, getData) => {
    if (!entry.isFile) return;

    try {
      // Handle aws-sdk package.json in node_modules
      if (entry.name.endsWith(AWS_SDK_PACKAGE_JSON)) {
        awsSdkPackageJsonMap.set(entry.name, (await getData()).toString());
      }

      // Handle files outside of node_modules
      else if (!entry.name.includes(`${NODE_MODULES}/`)) {
        // Handle package.json
        if (entry.name.endsWith(PACKAGE_JSON)) {
          packageJsonMap.set(entry.name, (await getData()).toString());
        }
        // Handle JS/TS files
        else if (entry.name.match(/\.(js|ts|mjs|cjs)$/)) {
          codeMap.set(entry.name, (await getData()).toString());
        }
      }
    } catch {
      // Continue if entry data can't be read.
    }
  });

  return {
    codeMap,
    ...(packageJsonMap.size > 0 && { packageJsonMap }),
    ...(awsSdkPackageJsonMap.size > 0 && { awsSdkPackageJsonMap }),
  };
};
