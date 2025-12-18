import { Lambda, paginateListFunctions } from "@aws-sdk/client-lambda";
import pLimit from "p-limit";

import { cpus } from "node:os";

import { JS_SDK_V2_MARKER, type LambdaCommandOptions } from "./constants.ts";
import { scanLambdaFunction } from "./scanLambdaFunction.ts";
import { getDownloadConfirmation } from "./utils/getDownloadConfirmation.ts";

export const scanLambdaFunctions = async ({ region, yes }: LambdaCommandOptions) => {
  const client = new Lambda({ region });
  const functions: string[] = [];

  let totalCodeSize = 0;
  const paginator = paginateListFunctions({ client }, {});
  for await (const page of paginator) {
    const nodeJsFunctions = (page.Functions ?? []).filter((fn) => fn.Runtime?.startsWith("nodejs"));
    totalCodeSize += nodeJsFunctions.reduce((acc, fn) => acc + (fn.CodeSize || 0), totalCodeSize);
    functions.push(...nodeJsFunctions.map((fn) => fn.FunctionName!));
  }

  if (functions.length === 0) {
    console.log("No functions found.");
    process.exit(0);
  }

  if (!yes) {
    const confirmation = await getDownloadConfirmation(functions.length, totalCodeSize);
    console.log();
    if (!confirmation) {
      console.log("Exiting.");
      process.exit(0);
    }
  }

  console.log(`Note about output:`);
  console.log(
    `- ${JS_SDK_V2_MARKER.Y} means "aws-sdk" is found in Lambda function, and migration is recommended.`,
  );
  console.log(`- ${JS_SDK_V2_MARKER.N} means "aws-sdk" is not found in Lambda function.`);
  console.log(
    `- ${JS_SDK_V2_MARKER.UNKNOWN} means script was not able to proceed, and it emits reason.\n`,
  );

  const clientRegion = await client.config.region();
  console.log(
    `Reading ${functions.length} function${functions.length > 1 ? "s" : ""} from "${clientRegion}" region.`,
  );

  const limit = pLimit(Math.min(functions.length, cpus().length || 1));
  await Promise.all(functions.map((fn) => limit(() => scanLambdaFunction(client, fn))));

  console.log("\nDone.");
};
