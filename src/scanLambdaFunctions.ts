import { Lambda } from "@aws-sdk/client-lambda";
import pLimit from "p-limit";

import { type LambdaCommandOptions } from "./constants.ts";
import { getLambdaFunctionScanOutput } from "./getLambdaFunctionScanOutput.ts";
import { getDownloadConfirmation } from "./utils/getDownloadConfirmation.ts";
import { getLambdaFunctions } from "./utils/getLambdaFunctions.ts";

export const scanLambdaFunctions = async ({ region, yes, jobs }: LambdaCommandOptions = {}) => {
  const client = new Lambda({ region });

  const functions = await getLambdaFunctions(client);
  const functionCount = functions.length;

  const concurrency = Math.min(functionCount, jobs || 1);
  const codeSizeToDownload = functions.reduce((acc, fn) => acc + (fn.CodeSize || 0), 0);
  const codeSizeToSaveOnDisk = functions
    .map((fn) => fn.CodeSize || 0)
    .sort((a, b) => b - a)
    .slice(0, concurrency)
    .reduce((acc, size) => acc + size, 0);

  if (functionCount === 0) {
    console.log("[]");
    process.exit(0);
  }

  if (!yes) {
    const confirmation = await getDownloadConfirmation(
      functionCount,
      codeSizeToDownload,
      codeSizeToSaveOnDisk,
    );
    console.log();
    if (!confirmation) {
      console.log("Exiting.");
      process.exit(0);
    }
  }

  const clientRegion = await client.config.region();

  const limit = pLimit(concurrency);
  const output = await Promise.all(
    functions.map((fn) =>
      limit(() =>
        getLambdaFunctionScanOutput(client, {
          functionName: fn.FunctionName!,
          region: clientRegion,
        }),
      ),
    ),
  );

  console.log(JSON.stringify(output, null, 2));
};
