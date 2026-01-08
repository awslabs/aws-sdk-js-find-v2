import type { Lambda, Layer, Runtime } from "@aws-sdk/client-lambda";
import StreamZip from "node-stream-zip";

import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AWS_SDK_PACKAGE_JSON, NODE_MODULES, PACKAGE_JSON } from "./constants.ts";
import { downloadFile } from "./downloadFile.ts";
import { getLambdaLayerContents, type LambdaLayerContents } from "./getLambdaLayerContents.ts";
import { getSdkVersionFromLambdaLayerContents } from "./getSdkVersionFromLambdaLayerContents.ts";

export interface LambdaFunctionContentsOptions {
  /**
   * The name of the Lambda function
   */
  functionName: string;

  /**
   * The presigned URL to download the Lambda Function code.
   */
  codeLocation: string;

  /**
   * The runtime of the Lambda function (e.g., nodejs20.x)
   */
  runtime: Runtime;

  /**
   * The function's layers
   */
  layers?: Layer[];
}

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

const lambdaLayerCache = new Map<string, LambdaLayerContents>();

/**
 * Downloads and extracts the contents of a Lambda Function from its code location.
 *
 * Downloads the zip, parses it, and returns:
 * - JS/TS source files (excluding node_modules)
 * - package.json files (excluding node_modules)
 * - aws-sdk package.json from node_modules (for version detection)
 *
 * @returns Extracted contents categorized by file type.
 */
export const getLambdaFunctionContents = async (
  client: Lambda,
  { functionName, codeLocation, runtime, layers = [] }: LambdaFunctionContentsOptions,
): Promise<LambdaFunctionContents> => {
  const codeMap = new Map<string, string>();
  const packageJsonMap = new Map<string, string>();
  const awsSdkPackageJsonMap = new Map<string, string>();

  // Populate awsSdkPackageJsonMap with layers first.
  for (const layer of layers) {
    if (!layer.Arn) continue;

    if (!lambdaLayerCache.has(layer.Arn)) {
      lambdaLayerCache.set(layer.Arn, new Map());
      const response = await client.getLayerVersionByArn({ Arn: layer.Arn });
      if (response.Content?.Location) {
        const layerZipPath = join(tmpdir(), `layer-${layer.Arn}.zip`);
        await downloadFile(response.Content.Location, layerZipPath);
        const layerContents = await getLambdaLayerContents(layerZipPath);
        lambdaLayerCache.set(layer.Arn, layerContents);
        await rm(layerZipPath, { force: true });
      }
    }

    const layerContents = lambdaLayerCache.get(layer.Arn) || new Map();
    const version = getSdkVersionFromLambdaLayerContents(layerContents, runtime);
    if (version) awsSdkPackageJsonMap.set(AWS_SDK_PACKAGE_JSON, JSON.stringify({ version }));
  }

  const zipPath = join(tmpdir(), `function-${functionName}.zip`);
  await downloadFile(codeLocation, zipPath);
  const zip = new StreamZip.async({ file: zipPath });

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
      if (zipEntry.name.endsWith(AWS_SDK_PACKAGE_JSON) && zipEntry.isFile) {
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
  await rm(zipPath, { force: true });
  return {
    codeMap,
    ...(packageJsonMap.size > 0 && { packageJsonMap }),
    ...(awsSdkPackageJsonMap.size > 0 && { awsSdkPackageJsonMap }),
  };
};
