import { AWS_SDK_PACKAGE_JSON } from "./constants.ts";
import { processZipEntries } from "./processZipEntries.ts";

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
  const results = await processZipEntries(zipPath, async (entry, getData) => {
    if (!entry.isFile || !entry.name.endsWith(AWS_SDK_PACKAGE_JSON)) return;
    try {
      const { version } = JSON.parse((await getData()).toString());
      return [entry.name, { version }] as const;
    } catch {
      // Continue without adding package.json file, if entry data can't be read or there's parse error.
    }
  });
  return new Map(results);
};
