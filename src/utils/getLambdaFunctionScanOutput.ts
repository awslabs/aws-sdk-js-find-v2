import type { Lambda } from "@aws-sdk/client-lambda";
import { downloadFile } from "./downloadFile.ts";
import {
  getLambdaFunctionContents,
  type LambdaFunctionContents,
} from "./getLambdaFunctionContents.ts";
import { hasSdkV2InBundle } from "./hasSdkV2InBundle.ts";

import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface LambdaFunctionScanOptions {
  // The name of the Lambda function
  functionName: string;

  // AWS region the Lambda function is deployed to
  region: string;
}

export interface LambdaFunctionScanOutput {
  // The name of the Lambda function
  FunctionName: string;

  // AWS region the Lambda function is deployed to
  Region: string;

  // Whether the Lambda function contains AWS SDK for JavaScript v2
  ContainsAwsSdkJsV2: boolean | null;

  // The location of AWS SDK for JavaScript v2 in the Lambda function, if present.
  AwsSdkJsV2Location?: string;

  // The error message if there was an error scanning the Lambda function.
  AwsSdkJsV2Error?: string;
}

export const getLambdaFunctionScanOutput = async (
  client: Lambda,
  { functionName, region }: LambdaFunctionScanOptions,
): Promise<LambdaFunctionScanOutput> => {
  const output: LambdaFunctionScanOutput = {
    FunctionName: functionName,
    Region: region,
    ContainsAwsSdkJsV2: null,
  };

  const response = await client.getFunction({ FunctionName: functionName });
  if (!response.Code?.Location) {
    output.AwsSdkJsV2Error = "Function Code location not found.";
    return output;
  }
  const zipPath = join(tmpdir(), `${functionName}.zip`);

  let lambdaFunctionContents: LambdaFunctionContents;
  try {
    await downloadFile(response.Code.Location, zipPath);
    lambdaFunctionContents = await getLambdaFunctionContents(zipPath);
  } catch (error) {
    output.AwsSdkJsV2Error =
      error instanceof Error
        ? `Error downloading or reading Lambda function code: ${error.message}`
        : "Error downloading or reading Lambda function code.";
    return output;
  } finally {
    await rm(zipPath, { force: true });
  }

  const { packageJsonFiles, bundleFile } = lambdaFunctionContents;

  // Search for "aws-sdk" in package.json dependencies if present.
  if (packageJsonFiles && packageJsonFiles.length > 0) {
    for (const { path: packageJsonPath, content: packageJsonContent } of packageJsonFiles) {
      try {
        const packageJson = JSON.parse(packageJsonContent);
        const dependencies = packageJson.dependencies || {};
        if ("aws-sdk" in dependencies) {
          output.ContainsAwsSdkJsV2 = true;
          output.AwsSdkJsV2Location = `Defined in dependencies of '${packageJsonPath}'`;
          return output;
        }
      } catch (error) {
        const errorPrefix = `Error parsing '${packageJsonPath}'`;
        output.AwsSdkJsV2Error =
          error instanceof Error ? `${errorPrefix}: ${error.message}` : errorPrefix;
        return output;
      }
    }
  }

  // Check for code of "aws-sdk" in bundle, if not found in package.json dependencies.
  if (bundleFile && hasSdkV2InBundle(bundleFile.content)) {
    output.ContainsAwsSdkJsV2 = true;
    output.AwsSdkJsV2Location = `Bundled in '${bundleFile.path}'`;
    return output;
  }

  // "aws-sdk" dependency/code not found.
  output.ContainsAwsSdkJsV2 = false;
  return output;
};
