import StreamZip from "node-stream-zip";
const PACKAGE_JSON_FILENAME = "package.json";

export type LambdaFunctionContents = {
  /**
   * String contents of all package.json files from Lambda Function.
   */
  packageJsonContents?: string[];

  /**
   * String contents of the index.js bundle file, if present.
   */
  bundleContent?: string;
};

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

  const packageJsonContents = [];

  let zipEntries: Record<string, StreamZip.ZipEntry> = {};
  try {
    zipEntries = await zip.entries();
  } catch {
    // Continue with empty object, if zip entries can't be read.
    // ToDo: add warning when logging is supported in future.
  }

  for (const zipEntry of Object.values(zipEntries)) {
    // Skip 'node_modules' directory, as it's not the customer source code.
    if (zipEntry.name.includes("node_modules/")) continue;

    // Skip anything which is not 'package.json'
    if (!zipEntry.name.endsWith(PACKAGE_JSON_FILENAME)) continue;

    // Skip if 'package.json' is not a file
    if (!zipEntry.isFile) continue;

    try {
      const packageJsonContent = await zip.entryData(zipEntry.name);
      packageJsonContents.push(packageJsonContent.toString());
    } catch {
      // Continue without adding package.json file, if entry data can't be read.
      // ToDo: add warning when logging is supported in future.
    }
  }

  if (packageJsonContents.length !== 0) {
    await zip.close();
    return { packageJsonContents };
  }

  for (const path of ["index.js", "index.mjs", "index.cjs"]) {
    if (!zipEntries[path]) continue;
    if (!zipEntries[path].isFile) continue;
    try {
      const bundleContent = await zip.entryData(path);
      await zip.close();
      return { bundleContent: bundleContent.toString() };
    } catch {
      // Continue processing next index file, if entry data can't be read.
      // ToDo: add warning when logging is supported in future.
    }
  }

  await zip.close();
  return {};
};
