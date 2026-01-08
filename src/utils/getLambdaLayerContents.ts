import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AWS_SDK_PACKAGE_JSON } from "./constants.ts";
import { downloadFile } from "./downloadFile.ts";
import { processZipEntries } from "./processZipEntries.ts";

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
export const getLambdaLayerContents = async (
  layerArn: string,
  codeLocation: string,
): Promise<LambdaLayerContents> => {
  const zipPath = join(tmpdir(), `layer-${layerArn.replace(/[/:]/g, "-")}.zip`);
  await downloadFile(codeLocation, zipPath);

  const results = await processZipEntries(zipPath, async (entry, getData) => {
    if (!entry.isFile || !entry.name.endsWith(AWS_SDK_PACKAGE_JSON)) return;
    try {
      const { version } = JSON.parse((await getData()).toString());
      return [entry.name, { version }] as const;
    } catch {
      // Continue without adding package.json file, if entry data can't be read or there's parse error.
    }
  });

  await rm(zipPath, { force: true });
  return new Map(results);
};
