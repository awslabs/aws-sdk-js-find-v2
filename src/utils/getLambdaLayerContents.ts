import StreamZip from "node-stream-zip";
import { AWS_SDK_PACKAGE_JSON } from "./constants.ts";

/**
 * Map with aws-sdk package.json filepath as key and contents as value.
 */
export type LambdaLayerContents = Map<string, { version: string }>;

/**
 * Extracts the contents of a Lambda layer zip file.
 * Parses the zip and returns aws-sdk package.json from node_modules
 *
 * @param zipPath - The path to the zip file of Lambda layer.
 * @returns Extracted contents categorized by file type.
 */
export const getLambdaLayerContents = async (zipPath: string): Promise<LambdaLayerContents> => {
  const zip = new StreamZip.async({ file: zipPath });
  const lambdaLayerContents = new Map<string, { version: string }>();

  let zipEntries: Record<string, StreamZip.ZipEntry> = {};
  try {
    zipEntries = await zip.entries();
  } catch {
    // Continue with empty object, if zip entries can't be read.
    // ToDo: add warning when logging is supported in future.
  }

  for (const zipEntry of Object.values(zipEntries)) {
    // Skip if it is not a file
    if (!zipEntry.isFile) continue;

    // Skip if it's not aws-sdk package.json file.
    if (!zipEntry.name.endsWith(AWS_SDK_PACKAGE_JSON)) continue;

    try {
      const packageJsonContent = await zip.entryData(zipEntry.name);
      const { version } = JSON.parse(packageJsonContent.toString());
      lambdaLayerContents.set(zipEntry.name, { version });
    } catch {
      // Continue without adding package.json file, if entry data can't be read or there's parse error.
      // ToDo: add warning when logging is supported in future.
    }
  }

  await zip.close();
  return lambdaLayerContents;
};
