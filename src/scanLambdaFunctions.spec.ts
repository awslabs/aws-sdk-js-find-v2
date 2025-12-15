import { describe, it, expect, vi, beforeEach } from "vitest";
import { scanLambdaFunctions } from "./scanLambdaFunctions.ts";
import { JS_SDK_V2_MARKER } from "./constants.ts";

vi.mock("@aws-sdk/client-lambda");
vi.mock("./scanLambdaFunction.ts");

const mockPaginateListFunctions = vi.hoisted(() => vi.fn());
const mockScanLambdaFunction = vi.hoisted(() => vi.fn());

vi.mock("@aws-sdk/client-lambda", () => ({
  Lambda: vi.fn(),
  paginateListFunctions: mockPaginateListFunctions,
}));

vi.mock("./scanLambdaFunction.ts", () => ({
  scanLambdaFunction: mockScanLambdaFunction,
}));

describe(scanLambdaFunctions.name, () => {
  beforeEach(() => {
    vi.clearAllMocks();
    console.log = vi.fn();
    process.exit = vi.fn() as any;
  });

  it("exits early when no functions found", async () => {
    mockPaginateListFunctions.mockReturnValue([{ Functions: [] }]);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith("No functions found.");
    expect(process.exit).toHaveBeenCalledWith(0);
  });

  it("filters and scans only Node.js functions", async () => {
    const functions = [
      { FunctionName: "node-fn-1", Runtime: "nodejs18.x" },
      { FunctionName: "python-fn", Runtime: "python3.9" },
      { FunctionName: "node-fn-2", Runtime: "nodejs20.x" },
      { FunctionName: "java-fn", Runtime: "java11" },
    ];

    mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith("Reading 2 functions.");
    expect(mockScanLambdaFunction).toHaveBeenCalledTimes(2);
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "node-fn-1");
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "node-fn-2");
  });

  it("handles functions without names", async () => {
    const functions = [
      { FunctionName: "valid-fn", Runtime: "nodejs18.x" },
      { Runtime: "nodejs18.x" }, // No FunctionName
      { FunctionName: undefined, Runtime: "nodejs18.x" },
    ];

    mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

    await scanLambdaFunctions();

    expect(mockScanLambdaFunction).toHaveBeenCalledTimes(1);
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "valid-fn");
  });

  it("processes multiple pages of functions", async () => {
    const page1 = { Functions: [{ FunctionName: "fn-1", Runtime: "nodejs18.x" }] };
    const page2 = { Functions: [{ FunctionName: "fn-2", Runtime: "nodejs20.x" }] };

    mockPaginateListFunctions.mockReturnValue([page1, page2]);

    await scanLambdaFunctions();

    expect(mockScanLambdaFunction).toHaveBeenCalledTimes(2);
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "fn-1");
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "fn-2");
  });

  it("displays correct output messages", async () => {
    const functions = [{ FunctionName: "test-fn", Runtime: "nodejs18.x" }];
    mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith("Note about output:");
    expect(console.log).toHaveBeenCalledWith(
      `- ${JS_SDK_V2_MARKER.Y} means "aws-sdk" is found in Lambda function, and migration is recommended.`
    );
    expect(console.log).toHaveBeenCalledWith(
      `- ${JS_SDK_V2_MARKER.N} means "aws-sdk" is not found in Lambda function.`
    );
    expect(console.log).toHaveBeenCalledWith(
      `- ${JS_SDK_V2_MARKER.UNKNOWN} means script was not able to proceed, and it emits reason.\n`
    );
    expect(console.log).toHaveBeenCalledWith("Reading 1 function.");
    expect(console.log).toHaveBeenCalledWith("\nDone.");
  });

  it("uses correct plural form for multiple functions", async () => {
    const functions = [
      { FunctionName: "fn-1", Runtime: "nodejs18.x" },
      { FunctionName: "fn-2", Runtime: "nodejs18.x" },
    ];
    mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith("Reading 2 functions.");
  });
});