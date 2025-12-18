import {
  type LambdaFunctionContents,
  getLambdaFunctionContents,
} from "./utils/getLambdaFunctionContents.ts";
import { JS_SDK_V2_MARKER } from "./constants.ts";
import type { Lambda } from "@aws-sdk/client-lambda";
import { downloadFile } from "./utils/downloadFile.ts";
import { hasSdkV2InBundle } from "./utils/hasSdkV2InBundle.ts";

import { join } from "node:path";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";

export const scanLambdaFunction = async (client: Lambda, functionName: string) => {
  const response = await client.getFunction({ FunctionName: functionName });
  if (!response.Code?.Location) {
    console.log(`${JS_SDK_V2_MARKER.UNKNOWN} ${functionName}: Code location not found.`);
    return;
  }
  const zipPath = join(tmpdir(), `${functionName}.zip`);

  let lambdaFunctionContents: LambdaFunctionContents;
  try {
    await downloadFile(response.Code.Location, zipPath);
    lambdaFunctionContents = await getLambdaFunctionContents(zipPath);
  } finally {
    await rm(zipPath, { force: true });
  }

  const { packageJsonContents, bundleContent } = lambdaFunctionContents;

  // Search for "aws-sdk" in package.json dependencies if present.
  if (packageJsonContents && packageJsonContents.length > 0) {
    for (const packageJsonContent of packageJsonContents) {
      try {
        const packageJson = JSON.parse(packageJsonContent);
        const dependencies = packageJson.dependencies || {};
        if ("aws-sdk" in dependencies) {
          console.log(`${JS_SDK_V2_MARKER.Y} ${functionName}`);
          return;
        }
        // oxlint-disable-next-line no-unused-vars
      } catch (error) {
        // Parsing failure for package.json which is rare, continue.
      }
    }
  }

  // Check for code of "aws-sdk" in bundle, if not found in package.json dependencies.
  if (bundleContent && hasSdkV2InBundle(bundleContent)) {
    console.log(`${JS_SDK_V2_MARKER.Y} ${functionName}`);
    return;
  }

  // "aws-sdk" dependency/code not found.
  console.log(`${JS_SDK_V2_MARKER.N} ${functionName}`);
};
