import { describe, it, expect, vi, beforeEach } from "vitest";
import { Lambda } from "@aws-sdk/client-lambda";
import pLimit from "p-limit";
import { scanLambdaFunctions } from "./scanLambdaFunctions.ts";
import { scanLambdaFunction } from "./scanLambdaFunction.ts";
import { getDownloadConfirmation } from "./utils/getDownloadConfirmation.ts";
import { getLambdaFunctions } from "./utils/getLambdaFunctions.ts";
import { JS_SDK_V2_MARKER } from "./constants.ts";

vi.mock("@aws-sdk/client-lambda");
vi.mock("./scanLambdaFunction.ts");
vi.mock("./utils/getDownloadConfirmation.ts");
vi.mock("./utils/getLambdaFunctions.ts");
vi.mock("p-limit");

const mockLambdaConstructor = vi.fn();
vi.mocked(Lambda, true).mockImplementation(function (this: any, config?: any) {
  mockLambdaConstructor(config);
  this.config = { region: vi.fn().mockResolvedValue("us-east-1") };
  return this;
} as any);

const mockScanLambdaFunction = vi.mocked(scanLambdaFunction);
const mockGetDownloadConfirmation = vi.mocked(getDownloadConfirmation);
const mockGetLambdaFunctions = vi.mocked(getLambdaFunctions);
const mockPLimit = vi.mocked(pLimit);

describe(scanLambdaFunctions.name, () => {
  beforeEach(() => {
    vi.clearAllMocks();
    console.log = vi.fn();
    process.exit = vi.fn() as any;
    mockPLimit.mockImplementation(() => (fn: () => Promise<void>) => fn());
    mockGetDownloadConfirmation.mockResolvedValue(true);
  });

  it("exits early when no functions found", async () => {
    mockGetLambdaFunctions.mockResolvedValue([]);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith("No functions found.");
    expect(process.exit).toHaveBeenCalledWith(0);
  });

  it("displays correct output messages", async () => {
    const functions = [{ FunctionName: "test-fn", Runtime: "nodejs18.x", CodeSize: 1000 }];
    mockGetLambdaFunctions.mockResolvedValue(functions);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith("Note about output:");
    expect(console.log).toHaveBeenCalledWith(
      `- ${JS_SDK_V2_MARKER.Y} means "aws-sdk" is found in Lambda function, and migration is recommended.`,
    );
    expect(console.log).toHaveBeenCalledWith(
      `- ${JS_SDK_V2_MARKER.N} means "aws-sdk" is not found in Lambda function.`,
    );
    expect(console.log).toHaveBeenCalledWith(
      `- ${JS_SDK_V2_MARKER.UNKNOWN} means script was not able to proceed, and it emits reason.\n`,
    );
    expect(console.log).toHaveBeenCalledWith('Reading 1 function from "us-east-1" region.');
    expect(console.log).toHaveBeenCalledWith("\nDone.");
  });

  it("uses correct plural form for multiple functions", async () => {
    const functions = [
      { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
      { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 1000 },
    ];
    mockGetLambdaFunctions.mockResolvedValue(functions);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith('Reading 2 functions from "us-east-1" region.');
  });

  it("creates Lambda client with specified region", async () => {
    mockGetLambdaFunctions.mockResolvedValue([]);

    await scanLambdaFunctions({ region: "us-west-2" });

    expect(mockLambdaConstructor).toHaveBeenCalledWith({ region: "us-west-2" });
  });

  it("creates Lambda client with undefined region when not specified", async () => {
    mockGetLambdaFunctions.mockResolvedValue([]);

    await scanLambdaFunctions();

    expect(mockLambdaConstructor).toHaveBeenCalledWith({ region: undefined });
  });

  describe("download confirmation", () => {
    it("prompts for confirmation when yes is not set", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 2000 },
      ];
      mockGetLambdaFunctions.mockResolvedValue(functions);

      await scanLambdaFunctions({ jobs: 4 });

      expect(mockGetDownloadConfirmation).toHaveBeenCalledWith(2, 3000, 3000);
    });

    it("skips confirmation when yes is true", async () => {
      const functions = [{ FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 }];
      mockGetLambdaFunctions.mockResolvedValue(functions);

      await scanLambdaFunctions({ yes: true });

      expect(mockGetDownloadConfirmation).not.toHaveBeenCalled();
    });

    it("exits when confirmation is declined", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 4000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 5000 },
      ];
      mockGetLambdaFunctions.mockResolvedValue(functions);
      mockGetDownloadConfirmation.mockResolvedValue(false);

      await scanLambdaFunctions({ jobs: 4 });

      expect(mockGetDownloadConfirmation).toHaveBeenCalledWith(2, 9000, 9000);
      expect(console.log).toHaveBeenCalledWith("Exiting.");
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    it("calculates codeSizeToSaveOnDisk as sum of top N largest functions", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 3000 },
        { FunctionName: "fn-3", Runtime: "nodejs18.x", CodeSize: 2000 },
        { FunctionName: "fn-4", Runtime: "nodejs18.x", CodeSize: 500 },
      ];
      mockGetLambdaFunctions.mockResolvedValue(functions);

      await scanLambdaFunctions({ jobs: 2 });

      // Total download: 6500, disk: top 2 (3000 + 2000) = 5000
      expect(mockGetDownloadConfirmation).toHaveBeenCalledWith(4, 6500, 5000);
    });
  });

  describe("concurrency with p-limit", () => {
    it("uses jobs as concurrency when less than functions.length", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-3", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-4", Runtime: "nodejs18.x", CodeSize: 1000 },
      ];
      mockGetLambdaFunctions.mockResolvedValue(functions);

      await scanLambdaFunctions({ jobs: 2 });

      expect(mockPLimit).toHaveBeenCalledWith(2);
    });

    it("uses concurrency of 1 when jobs is not specified", async () => {
      const functions = [{ FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 }];
      mockGetLambdaFunctions.mockResolvedValue(functions);

      await scanLambdaFunctions();

      expect(mockPLimit).toHaveBeenCalledWith(1);
    });

    it("uses functions.length as concurrency when less than jobs", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 1000 },
      ];
      mockGetLambdaFunctions.mockResolvedValue(functions);

      await scanLambdaFunctions({ jobs: 4 });

      expect(mockPLimit).toHaveBeenCalledWith(2);
    });
  });
});
