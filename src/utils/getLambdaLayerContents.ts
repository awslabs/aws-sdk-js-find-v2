import { AWS_SDK_PACKAGE_JSON } from "./constants.ts";
import { processZipEntries } from "./processZipEntries.ts";
import { processRemoteZip } from "./processRemoteZip.ts";

/**
 * Map with aws-sdk package.json filepath as key and contents as value.
 */
export type LambdaLayerContents = Map<string, { version: string }>;

/**
 * Downloads and extracts the contents of a Lambda layer from its presigned URL.
 * Parses the zip and returns aws-sdk package.json from node_modules
 *
 * @param layerArn - The ARN of the Lambda layer (used for temp file naming).
 * @param codeLocation - The presigned URL to download the Lambda layer.
 * @returns Extracted contents categorized by file type.
 */
export const getLambdaLayerContents = (layerArn: string, codeLocation: string) =>
  processRemoteZip(codeLocation, `layer-${layerArn}`, async (zipPath) => {
    const results = await processZipEntries(zipPath, async (entry, getData) => {
      if (!entry.isFile || !entry.name.endsWith(AWS_SDK_PACKAGE_JSON)) return;
      try {
        const { version } = JSON.parse((await getData()).toString());
        return [entry.name, { version }] as const;
      } catch {
        // Continue without adding package.json file, if entry data can't be read or there's parse error.
      }
    });
    return new Map(results) as LambdaLayerContents;
  });
