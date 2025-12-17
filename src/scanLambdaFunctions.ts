import { Lambda, paginateListFunctions, type FunctionConfiguration } from "@aws-sdk/client-lambda";
import { cpus } from "node:os";
import pLimit from "p-limit";

import { JS_SDK_V2_MARKER } from "./constants.ts";
import { scanLambdaFunction } from "./scanLambdaFunction.ts";

const getNodeJsFunctionNames = (functions: FunctionConfiguration[] | undefined) =>
  (functions ?? [])
    .filter((fn) => fn.Runtime?.startsWith("nodejs"))
    .map((fn) => fn.FunctionName)
    .filter((fnName): fnName is string => fnName !== undefined);

export const scanLambdaFunctions = async (region?: string) => {
  const client = new Lambda({ region });
  const functions: string[] = [];

  const paginator = paginateListFunctions({ client }, {});
  for await (const page of paginator) {
    functions.push(...getNodeJsFunctionNames(page.Functions));
  }

  const functionsLength = functions.length;
  if (functionsLength === 0) {
    console.log("No functions found.");
    process.exit(0);
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
    `Reading ${functionsLength} function${functionsLength > 1 ? "s" : ""} from "${clientRegion}" region.`,
  );

  const limit = pLimit(cpus().length);
  await Promise.all(functions.map((fn) => limit(() => scanLambdaFunction(client, fn))));

  console.log("\nDone.");
};
