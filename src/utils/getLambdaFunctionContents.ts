import StreamZip from "node-stream-zip";
import { AWS_SDK, NODE_MODULES, PACKAGE_JSON } from "./constants.ts";
import { join } from "node:path";

export interface FileInfo {
  // Path of the file within the zip archive.
  path: string;

  // Contents of the file.
  content: string;
}

export interface LambdaFunctionContents {
  /**
   * String contents of all package.json files from Lambda Function.
   */
  packageJsonFiles?: FileInfo[];

  /**
   * Map with aws-sdk package.json filepath as key and contents as value.
   */
  awsSdkPackageJsonMap?: Record<string, string>;

  /**
   * String contents of the index.js bundle file, if present.
   */
  bundleFile?: FileInfo;
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

  const packageJsonFiles = [];
  const awsSdkPackageJsonMap: Record<string, string> = {};

  let zipEntries: Record<string, StreamZip.ZipEntry> = {};
  try {
    zipEntries = await zip.entries();
  } catch {
    // Continue with empty object, if zip entries can't be read.
    // ToDo: add warning when logging is supported in future.
  }

  for (const zipEntry of Object.values(zipEntries)) {
    // Skip 'node_modules' directory, except when it's not aws-sdk package.json.
    if (zipEntry.name.includes(`${NODE_MODULES}/`)) {
      if (zipEntry.name.endsWith(join(NODE_MODULES, AWS_SDK, PACKAGE_JSON)) && zipEntry.isFile) {
        const packageJsonContent = await zip.entryData(zipEntry.name);
        awsSdkPackageJsonMap[zipEntry.name] = packageJsonContent.toString();
      }
      continue;
    }

    // Skip anything which is not 'package.json'
    if (!zipEntry.name.endsWith(PACKAGE_JSON)) continue;

    // Skip if 'package.json' is not a file
    if (!zipEntry.isFile) continue;

    try {
      const packageJsonContent = await zip.entryData(zipEntry.name);
      packageJsonFiles.push({
        path: zipEntry.name,
        content: packageJsonContent.toString(),
      });
    } catch {
      // Continue without adding package.json file, if entry data can't be read.
      // ToDo: add warning when logging is supported in future.
    }
  }

  if (packageJsonFiles.length !== 0) {
    await zip.close();
    return {
      packageJsonFiles,
      ...(awsSdkPackageJsonMap && { awsSdkPackageJsonMap }),
    };
  }

  for (const path of ["index.js", "index.mjs", "index.cjs"]) {
    if (!zipEntries[path]) continue;
    if (!zipEntries[path].isFile) continue;
    try {
      const bundleContent = await zip.entryData(path);
      await zip.close();
      return {
        bundleFile: {
          path,
          content: bundleContent.toString(),
        },
      };
    } catch {
      // Continue processing next index file, if entry data can't be read.
      // ToDo: add warning when logging is supported in future.
    }
  }

  await zip.close();
  return {};
};
