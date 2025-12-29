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
  // Output as JSON
  if (outputType === LambdaCommandOutputType.json) {
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  // Output as table
  const tableOutput: Record<string, { Region: string; ContainsAwsSdkJsV2: string }> = {};
  for (const scanOutput of output) {
    let notes =
      scanOutput.ContainsAwsSdkJsV2 === null
        ? "N/A."
        : scanOutput.ContainsAwsSdkJsV2
          ? "Yes."
          : "No.";

    if (scanOutput.AwsSdkJsV2Error !== undefined) {
      notes += ` ${scanOutput.AwsSdkJsV2Error}`;
    }
    if (scanOutput.AwsSdkJsV2Location !== undefined) {
      notes += ` ${scanOutput.AwsSdkJsV2Location}`;
    }

    tableOutput[scanOutput.FunctionName] = {
      Region: scanOutput.Region,
      ContainsAwsSdkJsV2: notes,
    };
  }
  console.table(tableOutput);
};
