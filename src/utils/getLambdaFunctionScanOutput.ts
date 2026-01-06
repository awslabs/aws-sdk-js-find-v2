import type { Lambda } from "@aws-sdk/client-lambda";
import { satisfies, validate } from "compare-versions";

import { downloadFile } from "./downloadFile.ts";
import {
  getLambdaFunctionContents,
  type LambdaFunctionContents,
} from "./getLambdaFunctionContents.ts";
import { getPossibleHandlerFiles } from "./getPossibleHandlerFiles.ts";
import { hasSdkV2InBundle } from "./hasSdkV2InBundle.ts";
import { hasSdkV2InFile } from "./hasSdkV2InFile.ts";

import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getCodePathToSdkVersionMap } from "./getCodePathToSdkVersionMap.ts";

export interface LambdaFunctionScanOptions {
  // The name of the Lambda function
  functionName: string;

  // AWS region the Lambda function is deployed to
  region: string;

  // Lambda Function's Node.js runtime
  runtime: string;

  // Semver range string to check for AWS SDK for JavaScript v2
  sdkVersionRange: string;
}

export interface LambdaFunctionScanOutput {
  // The name of the Lambda function
  FunctionName: string;

  // AWS region the Lambda function is deployed to
  Region: string;

  // Lambda Function's Node.js runtime
  Runtime: string;

  // Version of AWS SDK for JavaScript v2 searched for
  SdkVersion: string;

  // Whether the Lambda function contains AWS SDK for JavaScript v2
  ContainsAwsSdkJsV2: boolean | null;

  // Locations of AWS SDK for JavaScript v2 in the Lambda function source code, if present.
  AwsSdkJsV2Locations?: string[];

  // The error message if there was an error scanning the Lambda function.
  AwsSdkJsV2Error?: string;
}

/**
 * Scans a Lambda function to detect AWS SDK for JavaScript v2 usage.
 *
 * Downloads the function code, extracts it, and checks for JS SDK v2 signature in handled file if it's a bundle.
 * If not found, it checks for source code files has require/imports JS SDK v2. It also checks dependencies in
 * package.json for version validation.
 *
 * @param client - AWS Lambda client instance
 * @param options - Scan configuration options
 * @param options.functionName - The name of the Lambda function
 * @param options.region - AWS region the Lambda function is deployed to
 * @param options.runtime - Lambda Function's Node.js runtime
 * @param options.sdkVersionRange - Semver range string to check for AWS SDK for JavaScript v2
 * @returns Scan results including SDK v2 detection status and locations
 */
export const getLambdaFunctionScanOutput = async (
  client: Lambda,
  { functionName, region, runtime, sdkVersionRange }: LambdaFunctionScanOptions,
): Promise<LambdaFunctionScanOutput> => {
  const output: LambdaFunctionScanOutput = {
    FunctionName: functionName,
    Region: region,
    Runtime: runtime,
    SdkVersion: sdkVersionRange,
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
    const errorPrefix = "Error downloading or reading Lambda function code";
    output.AwsSdkJsV2Error =
      error instanceof Error ? `${errorPrefix}: ${error.message}` : errorPrefix;
    return output;
  } finally {
    await rm(zipPath, { force: true });
  }

  const { packageJsonMap, awsSdkPackageJsonMap, codeMap } = lambdaFunctionContents;

  // Process handler as bundle file first.
  const possibleHandlerFiles = getPossibleHandlerFiles(
    response.Configuration?.Handler ?? "index.handler",
  );
  for (const handlerFile of possibleHandlerFiles) {
    const handlerContent = codeMap.get(handlerFile);
    if (handlerContent !== undefined) {
      if (hasSdkV2InBundle(handlerContent, sdkVersionRange)) {
        output.ContainsAwsSdkJsV2 = true;
        output.AwsSdkJsV2Locations = [handlerFile];
        return output;
      }
    }
  }

  const filesWithJsSdkV2: string[] = [];

  // Search for JS SDK v2 occurrence in source code
  for (const [filePath, fileContent] of codeMap) {
    try {
      if (hasSdkV2InFile(filePath, fileContent)) {
        filesWithJsSdkV2.push(filePath);
      }
    } catch {
      // Skip files that fail to parse
      // ToDo: add warning when logging is supported in future.
    }
  }

  // JS SDK v2 not found in source code.
  if (filesWithJsSdkV2.length === 0) {
    output.ContainsAwsSdkJsV2 = false;
    return output;
  }

  const codePathToSdkVersionMap = getCodePathToSdkVersionMap(
    filesWithJsSdkV2,
    packageJsonMap,
    awsSdkPackageJsonMap,
  );

  const jsSdkV2FilesInSdkVersionRange = [];
  for (const [codePath, version] of codePathToSdkVersionMap) {
    if (version && validate(version)) {
      try {
        if (satisfies(version, sdkVersionRange)) {
          jsSdkV2FilesInSdkVersionRange.push(codePath);
        }
      } catch {
        // Ignore if satisfies throws error
        // ToDo: add warning when logging is supported in future.
      }
    }
  }

  if (jsSdkV2FilesInSdkVersionRange.length > 0) {
    output.ContainsAwsSdkJsV2 = true;
    output.AwsSdkJsV2Locations = jsSdkV2FilesInSdkVersionRange;
    return output;
  }

  output.ContainsAwsSdkJsV2 = false;
  return output;
};
