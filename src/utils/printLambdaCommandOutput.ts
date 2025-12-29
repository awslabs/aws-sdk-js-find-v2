import type { LambdaFunctionScanOutput } from "./getLambdaFunctionScanOutput.ts";

export const LambdaCommandOutputType = {
  // prints output as JSON
  json: "json",

  // prints human-readable representation in a table
  table: "table",
} as const;

export type LambdaCommandOutputType =
  (typeof LambdaCommandOutputType)[keyof typeof LambdaCommandOutputType];

export const printLambdaCommandOutput = (
  output: LambdaFunctionScanOutput[],
  outputType: LambdaCommandOutputType,
) => {
  if (outputType === LambdaCommandOutputType.json) {
    console.log(JSON.stringify(output, null, 2));
    return;
  }
};
