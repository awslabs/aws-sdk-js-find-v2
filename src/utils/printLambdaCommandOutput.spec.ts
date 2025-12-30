import { describe, it, expect, vi, beforeEach } from "vitest";
import type { LambdaFunctionScanOutput } from "./getLambdaFunctionScanOutput.ts";

const mockPush = vi.fn();
const mockToString = vi.fn().mockReturnValue("table-output");
vi.mock("cli-table3", () => ({
  default: class {
    push = mockPush;
    toString = mockToString;
  },
}));

import { printLambdaCommandOutput, LambdaCommandOutputType } from "./printLambdaCommandOutput.ts";

describe("printLambdaCommandOutput", () => {
  const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockOutput: LambdaFunctionScanOutput[] = [
    { FunctionName: "fn1", Region: "us-east-1", Runtime: "nodejs20.x", ContainsAwsSdkJsV2: false },
    {
      FunctionName: "fn2",
      Region: "us-west-2",
      Runtime: "nodejs18.x",
      ContainsAwsSdkJsV2: true,
      AwsSdkJsV2Location: "Bundled in 'index.js'",
    },
    {
      FunctionName: "fn3",
      Region: "eu-west-1",
      Runtime: "nodejs16.x",
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Error occurred",
    },
  ];

  it("outputs JSON when outputType is json", () => {
    printLambdaCommandOutput(mockOutput, LambdaCommandOutputType.json);
    expect(consoleSpy).toHaveBeenCalledWith(JSON.stringify(mockOutput, null, 2));
  });

  it("outputs table when outputType is table", () => {
    printLambdaCommandOutput(mockOutput, LambdaCommandOutputType.table);
    expect(mockPush).toHaveBeenCalledWith(["fn1", "us-east-1", "nodejs20.x", "No."]);
    expect(mockPush).toHaveBeenCalledWith([
      "fn2",
      "us-west-2",
      "nodejs18.x",
      "Yes. Bundled in 'index.js'",
    ]);
    expect(mockPush).toHaveBeenCalledWith([
      "fn3",
      "eu-west-1",
      "nodejs16.x",
      "N/A. Error occurred",
    ]);
    expect(consoleSpy).toHaveBeenCalledWith("table-output");
  });
});
