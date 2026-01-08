import type { Runtime } from "@aws-sdk/client-lambda";
import { AWS_SDK_PACKAGE_JSON } from "./constants.ts";
import type { LambdaLayerContents } from "./getLambdaLayerContents.ts";

/**
 * Returns version from aws-sdk package.json value based on specificity
 * - nodejs/node{major-version}/node_modules
 * - nodejs/node_modules
 * - node_modules
 *
 * @param lambdaLayerContents - Map with aws-sdk package.json filepath as key and contents as value.
 * @param runtime - Lambda runtime (e.g., nodejs20.x)
 * @returns The sdk version string, or undefined if not found.
 */
export const getSdkVersionFromLambdaLayerContents = (
  lambdaLayerContents: LambdaLayerContents,
  runtime: Runtime,
): string | undefined => {
  const majorVersion = runtime.match(/nodejs(\d+)/)?.[1];
  const paths = [
    `nodejs/node${majorVersion}/${AWS_SDK_PACKAGE_JSON}`,
    `nodejs/${AWS_SDK_PACKAGE_JSON}`,
    AWS_SDK_PACKAGE_JSON,
  ];

  for (const path of paths) {
    const content = lambdaLayerContents.get(path);
    if (content) return content.version;
  }
};
