import { Lambda } from "@aws-sdk/client-lambda";
import pLimit from "p-limit";

import { getDownloadConfirmation } from "./utils/getDownloadConfirmation.ts";
import { getCodeSizeToDownload } from "./utils/getCodeSizeToDownload.ts";
import { getCodeSizeToSaveOnDisk } from "./utils/getCodeSizeToSaveOnDisk.ts";
import { getLambdaFunctions } from "./utils/getLambdaFunctions.ts";
import { getLambdaFunctionScanOutput } from "./utils/getLambdaFunctionScanOutput.ts";
import { getLambdaNodeJsMatchingVersions } from "./utils/getLambdaNodeJsMatchingVersions.ts";
import {
  LambdaCommandOutputType,
  printLambdaCommandOutput,
} from "./utils/printLambdaCommandOutput.ts";

export interface ScanLambdaFunctionsOptions {
  // answer yes for all prompts
  yes: boolean;

  // Semver range string to select Lambda Node.js major versions
  node: string;

  // Semver range string to check for AWS SDK for JavaScript v2
  sdk: string;

  // AWS region to scan
  region?: string;

  // AWS profile to use from credentials or config file.
  profile?: string;

  // output type to produce
  output: LambdaCommandOutputType;

  // maximum number of jobs to run concurrently; caller must provide this value
  jobs: number;
}

export const scanLambdaFunctions = async (options: ScanLambdaFunctionsOptions) => {
  const { yes, node, sdk, region, profile, output, jobs } = options;
  const client = new Lambda({
    ...(region && { region }),
    ...(profile && { profile }),
  });

  const lambdaNodeJsMajorVersions = getLambdaNodeJsMatchingVersions(node);
  if (lambdaNodeJsMajorVersions.length === 0) {
    printLambdaCommandOutput([], output);
    return;
  }

  const functions = await getLambdaFunctions(client, lambdaNodeJsMajorVersions);
  const functionCount = functions.length;

  if (functionCount === 0) {
    printLambdaCommandOutput([], output);
    return;
  }

  const concurrency = Math.min(functionCount, jobs || 1);

  if (!yes) {
    const confirmation = await getDownloadConfirmation(
      functionCount,
      getCodeSizeToDownload(functions),
      getCodeSizeToSaveOnDisk(functions, concurrency),
    );
    console.log();
    if (!confirmation) {
      console.log("Exiting.");
      return;
    }
  }

  const clientRegion = await client.config.region();

  const limit = pLimit(concurrency);
  const scanOutput = await Promise.all(
    functions.map((fn) =>
      limit(() =>
        getLambdaFunctionScanOutput(client, {
          functionName: fn.FunctionName!,
          region: clientRegion,
          sdkVersionRange: sdk,
        }),
      ),
    ),
  );

  printLambdaCommandOutput(scanOutput, output);
};
