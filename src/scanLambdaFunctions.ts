import { JS_SDK_V2_MARKER, type LambdaCommandOptions } from "./constants.ts";
import { Lambda } from "@aws-sdk/client-lambda";
import { cpus } from "node:os";
import { getDownloadConfirmation } from "./utils/getDownloadConfirmation.ts";
import { getLambdaFunctions } from "./utils/getLambdaFunctions.ts";
import pLimit from "p-limit";
import { scanLambdaFunction } from "./scanLambdaFunction.ts";

export const scanLambdaFunctions = async ({ region, yes }: LambdaCommandOptions = {}) => {
  const client = new Lambda({ region });

  const functions = await getLambdaFunctions(client);
  const totalCodeSize = functions.reduce((acc, fn) => acc + (fn.CodeSize || 0), 0);

  const functionCount = functions.length;
  if (functionCount === 0) {
    console.log("No functions found.");
    process.exit(0);
  }

  if (!yes) {
    const confirmation = await getDownloadConfirmation(functionCount, totalCodeSize);
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
    `Reading ${functionCount} function${functionCount > 1 ? "s" : ""} from "${clientRegion}" region.`,
  );

  const limit = pLimit(Math.min(functionCount, cpus().length || 1));
  await Promise.all(
    functions.map((fn) => limit(() => scanLambdaFunction(client, fn.FunctionName!))),
  );

  console.log("\nDone.");
};
