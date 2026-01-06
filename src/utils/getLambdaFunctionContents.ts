import StreamZip from "node-stream-zip";
import { AWS_SDK, NODE_MODULES, PACKAGE_JSON } from "./constants.ts";
import { join } from "node:path";

export interface LambdaFunctionContents {
  /**
   * Map with JS/TS filepath as key and contents as value.
   */
  codeMap: Record<string, string>;

  /**
   * Map with package.json filepath as key and contents as value.
   */
  packageJsonMap?: Record<string, string>;

  /**
   * Map with aws-sdk package.json filepath as key and contents as value.
   */
  awsSdkPackageJsonMap?: Record<string, string>;
}

/**
 * Extracts the contents of a Lambda Function zip file.
 * Returns string contents of package.json files, if available.
 * Otherwise, returns the contents of bundle file.
 *
 * @param zipPath - The path to the zip file of Lambda Function.
 * @returns Promise<LambdaFunctionContents> - Resolves to an object containing the extracted contents.
 */
export const getLambdaFunctionContents = async (
  zipPath: string,
): Promise<LambdaFunctionContents> => {
  const zip = new StreamZip.async({ file: zipPath });

  const codeMap: Record<string, string> = {};
  const packageJsonMap: Record<string, string> = {};
  const awsSdkPackageJsonMap: Record<string, string> = {};

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
        awsSdkPackageJsonMap[zipEntry.name] = packageJsonContent.toString();
      }
      continue;
    }

    // Skip if it is not a file
    if (!zipEntry.isFile) continue;

    // Populate 'package.json' files.
    if (zipEntry.name.endsWith(PACKAGE_JSON)) {
      try {
        const packageJsonContent = await zip.entryData(zipEntry.name);
        packageJsonMap[zipEntry.name] = packageJsonContent.toString();
      } catch {
        // Continue without adding package.json file, if entry data can't be read.
        // ToDo: add warning when logging is supported in future.
      }
      continue;
    }

    // Populate JavaScript files.
    if (zipEntry.name.match(/\.(js|ts|mjs|cjs)$/)) {
      try {
        const javascriptContent = await zip.entryData(zipEntry.name);
        codeMap[zipEntry.name] = javascriptContent.toString();
      } catch {
        // Continue without adding JavaScript file, if entry data can't be read.
        // ToDo: add warning when logging is supported in future.
      }
      continue;
    }
  }

  await zip.close();
  return {
    codeMap,
    ...(Object.keys(packageJsonMap).length > 0 && { packageJsonMap }),
    ...(Object.keys(awsSdkPackageJsonMap).length > 0 && { awsSdkPackageJsonMap }),
  };
};
