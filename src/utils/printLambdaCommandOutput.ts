import type { LambdaFunctionScanOutput } from "./getLambdaFunctionScanOutput.ts";
import Table from "cli-table3";

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
  const table = new Table({
    head: ["FunctionName", "Region", "Runtime", "ContainsAwsSdkJsV2"],
    style: { head: ["bold"] },
  });
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

    table.push([scanOutput.FunctionName, scanOutput.Region, scanOutput.Runtime, notes]);
  }
  console.log(table.toString());
};
