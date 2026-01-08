import type { Lambda, Layer, Runtime } from "@aws-sdk/client-lambda";

import { AWS_SDK_PACKAGE_JSON, NODE_MODULES, PACKAGE_JSON } from "./constants.ts";
import { getLambdaLayerContents, type LambdaLayerContents } from "./getLambdaLayerContents.ts";
import { getSdkVersionFromLambdaLayerContents } from "./getSdkVersionFromLambdaLayerContents.ts";
import { processRemoteZip } from "./processRemoteZip.ts";
import { processZipEntries } from "./processZipEntries.ts";

export interface LambdaFunctionContentsOptions {
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

/**
 * Cache for Lambda layer contents to avoid redundant downloads.
 * Maps layer ARN to extracted layer contents.
 */
const lambdaLayerCache = new Map<string, LambdaLayerContents>();

/**
 * Extracts and categorizes contents from a Lambda Function deployment package.
 *
 * Downloads and processes the Lambda function's zip file to extract:
 * - JavaScript/TypeScript source files (excluding node_modules)
 * - package.json files (excluding node_modules)
 * - AWS SDK package.json files from node_modules and layers (for version detection)
 *
 * @param client - The Lambda client instance for API calls
 * @param options - Configuration options for content extraction
 * @param options.codeLocation - Presigned URL to download the Lambda function code
 * @param options.runtime - Lambda runtime identifier (e.g., 'nodejs20.x')
 * @param options.layers - Array of Lambda layers attached to the function
 * @returns Promise resolving to categorized file contents with optional maps for package.json and AWS SDK files
 */
export const getLambdaFunctionContents = async (
  client: Lambda,
  { codeLocation, runtime, layers = [] }: LambdaFunctionContentsOptions,
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
        ? await getLambdaLayerContents(response.Content.Location)
        : new Map();
      lambdaLayerCache.set(layer.Arn, layerContents);
    }

    const layerContents = lambdaLayerCache.get(layer.Arn) || new Map();
    const version = getSdkVersionFromLambdaLayerContents(layerContents, runtime);
    if (version) awsSdkPackageJsonMap.set(AWS_SDK_PACKAGE_JSON, JSON.stringify({ version }));
  }

  await processRemoteZip(codeLocation, async (zipPath) => {
    await processZipEntries(zipPath, async (entry, getData) => {
      if (!entry.isFile) return;

      try {
        // Handle aws-sdk package.json in node_modules
        if (entry.name.endsWith(AWS_SDK_PACKAGE_JSON)) {
          awsSdkPackageJsonMap.set(entry.name, (await getData()).toString());
        }

        // Handle files outside of node_modules
        else if (!entry.name.includes(`${NODE_MODULES}/`)) {
          // Handle package.json
          if (entry.name.endsWith(PACKAGE_JSON)) {
            packageJsonMap.set(entry.name, (await getData()).toString());
          }
          // Handle JS/TS files
          else if (entry.name.match(/\.(js|ts|mjs|cjs)$/)) {
            codeMap.set(entry.name, (await getData()).toString());
          }
        }
      } catch {
        // Continue if entry data can't be read.
      }
    });
  });

  return {
    codeMap,
    ...(packageJsonMap.size > 0 && { packageJsonMap }),
    ...(awsSdkPackageJsonMap.size > 0 && { awsSdkPackageJsonMap }),
  };
};
