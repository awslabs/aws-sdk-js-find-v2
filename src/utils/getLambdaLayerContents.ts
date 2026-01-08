import { AWS_SDK_PACKAGE_JSON } from "./constants.ts";
import { processZipEntries } from "./processZipEntries.ts";
import { processRemoteZip } from "./processRemoteZip.ts";

/**
 * Map containing aws-sdk package.json files found in Lambda layer contents.
 * Key: filepath to aws-sdk package.json file
 * Value: object containing the version from the package.json
 */
export type LambdaLayerContents = Map<string, { version: string }>;

/**
 * Downloads and extracts the contents of a Lambda layer from its presigned URL.
 * Parses the zip and returns aws-sdk package.json from node_modules
 *
 * @param codeLocation - The presigned URL to download the Lambda layer.
 * @returns Map of aws-sdk package.json files with their versions found in the layer.
 */
export const getLambdaLayerContents = async (codeLocation: string) => {
  const lambdaLayerContents = new Map();
  await processRemoteZip(codeLocation, async (zipPath) => {
    await processZipEntries(zipPath, async (entry, getData) => {
      if (!entry.isFile || !entry.name.endsWith(AWS_SDK_PACKAGE_JSON)) return;
      try {
        const { version } = JSON.parse((await getData()).toString());
        lambdaLayerContents.set(entry.name, { version });
      } catch {
        // Continue without adding package.json file, if entry data can't be read or there's parse error.
      }
    });
  });
  return lambdaLayerContents;
};
