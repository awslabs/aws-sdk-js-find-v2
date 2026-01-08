import type { Lambda, Layer, Runtime } from "@aws-sdk/client-lambda";

import { AWS_SDK_PACKAGE_JSON, NODE_MODULES, PACKAGE_JSON } from "./constants.ts";
import { getLambdaLayerContents, type LambdaLayerContents } from "./getLambdaLayerContents.ts";
import { getSdkVersionFromLambdaLayerContents } from "./getSdkVersionFromLambdaLayerContents.ts";
import { processZipEntries } from "./processZipEntries.ts";
import { processRemoteZip } from "./processRemoteZip.ts";

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
      const response = await client.getLayerVersionByArn({ Arn: layer.Arn });
      const layerContents = response.Content?.Location
        ? await getLambdaLayerContents(layer.Arn, response.Content.Location)
        : new Map();
      lambdaLayerCache.set(layer.Arn, layerContents);
    }

    const layerContents = lambdaLayerCache.get(layer.Arn) || new Map();
    const version = getSdkVersionFromLambdaLayerContents(layerContents, runtime);
    if (version) awsSdkPackageJsonMap.set(AWS_SDK_PACKAGE_JSON, JSON.stringify({ version }));
  }

  return processRemoteZip(codeLocation, `function-${functionName}`, async (zipPath) => {
    await processZipEntries(zipPath, async (entry, getData) => {
      // Handle aws-sdk package.json in node_modules
      if (entry.name.includes(`${NODE_MODULES}/`)) {
        if (entry.name.endsWith(AWS_SDK_PACKAGE_JSON) && entry.isFile) {
          try {
            awsSdkPackageJsonMap.set(entry.name, (await getData()).toString());
          } catch {
            // Continue if entry data can't be read.
          }
        }
        return;
      }

      if (!entry.isFile) return;

      try {
        if (entry.name.endsWith(PACKAGE_JSON)) {
          packageJsonMap.set(entry.name, (await getData()).toString());
        } else if (entry.name.match(/\.(js|ts|mjs|cjs)$/)) {
          codeMap.set(entry.name, (await getData()).toString());
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
  });
};
