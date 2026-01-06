import type { Lambda } from "@aws-sdk/client-lambda";
import { satisfies, validate } from "compare-versions";

import { downloadFile } from "./downloadFile.ts";
import {
  getLambdaFunctionContents,
  type LambdaFunctionContents,
} from "./getLambdaFunctionContents.ts";

import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { AWS_SDK, NODE_MODULES, PACKAGE_JSON } from "./constants.ts";
import { hasSdkV2InFile } from "./hasSdkV2InFile.ts";
import { hasSdkV2InBundle } from "./hasSdkV2InBundle.ts";

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
 * Downloads the function code, extracts it, and checks for v2 SDK in:
 * 1. package.json dependencies
 * 2. Bundled index file
 *
 * @param client - AWS Lambda client instance
 * @param options - Scan configuration options
 * @returns Scan results including SDK v2 detection status and location
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

  const filesWithSdkV2: string[] = [];

  // Search for JS SDK v2 occurrence in source code
  for (const [filePath, fileContent] of Object.entries(codeMap)) {
    if (await hasSdkV2InFile(filePath, fileContent)) {
      filesWithSdkV2.push(filePath);
    }
  }

  // JS SDK v2 not found in souce code.
  if (filesWithSdkV2.length === 0) {
    output.ContainsAwsSdkJsV2 = false;
    return output;
  }

  // Search for JS SDK v2 version from package.json
  if (packageJsonMap && Object.keys(packageJsonMap).length > 0) {
    for (const [packageJsonPath, packageJsonContent] of Object.entries(packageJsonMap)) {
      try {
        const packageJson = JSON.parse(packageJsonContent);
        const dependencies = packageJson.dependencies || {};
        if (AWS_SDK in dependencies) {
          const awsSdkVersionInPackageJson: string = dependencies[AWS_SDK];

          const awsSdkPackageJsonPathInNodeModules = join(NODE_MODULES, AWS_SDK, PACKAGE_JSON);
          // Get aws-sdk package.json from nested node_modules or root node_modules.
          const awsSdkPackageJson = awsSdkPackageJsonMap
            ? (awsSdkPackageJsonMap[
                join(dirname(packageJsonPath), awsSdkPackageJsonPathInNodeModules)
              ] ?? awsSdkPackageJsonMap[awsSdkPackageJsonPathInNodeModules])
            : undefined;

          let awsSdkVersionInNodeModules: string | undefined;
          try {
            if (awsSdkPackageJson) {
              awsSdkVersionInNodeModules = JSON.parse(awsSdkPackageJson).version;
            }
          } catch {
            // Skip if JSON can't be parsed.
            // ToDo: add warning when logging is supported in future.
          }

          const sdkVersionToCheck =
            validate(awsSdkVersionInPackageJson) || awsSdkPackageJson === undefined
              ? // Use version in package.json dependencies, if fixed version is defined or aws-sdk package.json is not available.
                awsSdkVersionInPackageJson
              : // Use version from aws-sdk package.json, if defined
                (awsSdkVersionInNodeModules ?? awsSdkVersionInPackageJson);

          try {
            if (!satisfies(sdkVersionToCheck, sdkVersionRange)) {
              continue;
            }
          } catch (error) {
            const errorPrefix = `Error checking version range '${sdkVersionRange}' for aws-sdk@${
              dependencies["aws-sdk"]
            } in '${packageJsonPath}'`;
            output.AwsSdkJsV2Error =
              error instanceof Error ? `${errorPrefix}: ${error.message}` : errorPrefix;
            return output;
          }
          output.ContainsAwsSdkJsV2 = true;
          output.AwsSdkJsV2Locations = filesWithSdkV2;
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

  // Treat detected files as bundle files and check for version range
  else {
    for (const filePath of filesWithSdkV2) {
      try {
        if (hasSdkV2InBundle(codeMap[filePath], sdkVersionRange)) {
          output.ContainsAwsSdkJsV2 = true;
          output.AwsSdkJsV2Locations = filesWithSdkV2;
          return output;
        }
      } catch (error) {
        const errorPrefix = `Error reading bundle '${filePath}' for aws-sdk@${sdkVersionRange}`;
        output.AwsSdkJsV2Error =
          error instanceof Error ? `${errorPrefix}: ${error.message}` : errorPrefix;
        return output;
      }
    }
  }

  // JS SDK v2 dependency/code not found.
  output.ContainsAwsSdkJsV2 = false;
  return output;
};
