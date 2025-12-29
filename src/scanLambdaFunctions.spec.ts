import { describe, it, expect, vi, beforeEach } from "vitest";
import { type FunctionConfiguration, Lambda } from "@aws-sdk/client-lambda";
import pLimit from "p-limit";

import { getDownloadConfirmation } from "./utils/getDownloadConfirmation.ts";
import { getLambdaFunctions } from "./utils/getLambdaFunctions.ts";
import { getLambdaFunctionScanOutput } from "./getLambdaFunctionScanOutput.ts";
import { scanLambdaFunctions } from "./scanLambdaFunctions.ts";

vi.mock("@aws-sdk/client-lambda");
vi.mock("./getLambdaFunctionScanOutput.ts");
vi.mock("./utils/getDownloadConfirmation.ts");
vi.mock("./utils/getLambdaFunctions.ts");
vi.mock("p-limit");

describe("scanLambdaFunctions", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    console.log = vi.fn();
    process.exit = vi.fn() as any;

    vi.mocked(pLimit).mockImplementation(() => (fn: () => Promise<void>) => fn());
    vi.mocked(getDownloadConfirmation).mockResolvedValue(true);
    vi.mocked(Lambda).mockImplementation(function () {
      return {
        config: { region: vi.fn().mockResolvedValue("us-east-1") },
      };
    });
  });

  it("exits early when no functions found", async () => {
    vi.mocked(getLambdaFunctions).mockResolvedValue([]);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith("[]");
    expect(process.exit).toHaveBeenCalledWith(0);
    expect(getLambdaFunctionScanOutput).not.toHaveBeenCalled();
  });

  it("outputs JSON result", async () => {
    const functions = [
      { FunctionName: "test-fn", Runtime: "nodejs18.x", CodeSize: 1000 },
    ] as FunctionConfiguration[];
    const scanOutput = { FunctionName: "test-fn", Region: "us-east-1", ContainsAwsSdkJsV2: false };
    vi.mocked(getLambdaFunctions).mockResolvedValue(functions);
    vi.mocked(getLambdaFunctionScanOutput).mockResolvedValue(scanOutput);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith(JSON.stringify([scanOutput], null, 2));
  });

  it("creates Lambda client with specified region", async () => {
    vi.mocked(getLambdaFunctions).mockResolvedValue([]);

    await scanLambdaFunctions({ region: "us-west-2" });

    expect(Lambda).toHaveBeenCalledWith({ region: "us-west-2" });
  });

  it("creates Lambda client with undefined region when not specified", async () => {
    vi.mocked(getLambdaFunctions).mockResolvedValue([]);

    await scanLambdaFunctions();

    expect(Lambda).toHaveBeenCalledWith({ region: undefined });
  });

  describe("download confirmation", () => {
    it("prompts for confirmation when yes is not set", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 2000 },
      ] as FunctionConfiguration[];
      vi.mocked(getLambdaFunctions).mockResolvedValue(functions);

      await scanLambdaFunctions({ jobs: 4 });

      expect(getDownloadConfirmation).toHaveBeenCalledWith(2, 3000, 3000);
    });

    it("skips confirmation when yes is true", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
      ] as FunctionConfiguration[];
      vi.mocked(getLambdaFunctions).mockResolvedValue(functions);

      await scanLambdaFunctions({ yes: true });

      expect(getDownloadConfirmation).not.toHaveBeenCalled();
    });

    it("exits when confirmation is declined", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 4000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 5000 },
      ] as FunctionConfiguration[];
      vi.mocked(getLambdaFunctions).mockResolvedValue(functions);
      vi.mocked(getDownloadConfirmation).mockResolvedValue(false);

      await scanLambdaFunctions({ jobs: 4 });

      expect(getDownloadConfirmation).toHaveBeenCalledWith(2, 9000, 9000);
      expect(console.log).toHaveBeenCalledWith("Exiting.");
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    it("calculates codeSizeToSaveOnDisk as sum of top N largest functions", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 3000 },
        { FunctionName: "fn-3", Runtime: "nodejs18.x", CodeSize: 2000 },
        { FunctionName: "fn-4", Runtime: "nodejs18.x", CodeSize: 500 },
      ] as FunctionConfiguration[];
      vi.mocked(getLambdaFunctions).mockResolvedValue(functions);

      await scanLambdaFunctions({ jobs: 2 });

      // Total download: 6500, disk: top 2 (3000 + 2000) = 5000
      expect(getDownloadConfirmation).toHaveBeenCalledWith(4, 6500, 5000);
    });
  });

  describe("concurrency with p-limit", () => {
    it("uses jobs as concurrency when less than functions.length", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-3", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-4", Runtime: "nodejs18.x", CodeSize: 1000 },
      ] as FunctionConfiguration[];
      vi.mocked(getLambdaFunctions).mockResolvedValue(functions);

      await scanLambdaFunctions({ jobs: 2 });

      expect(pLimit).toHaveBeenCalledWith(2);
    });

    it("uses concurrency of 1 when jobs is not specified", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
      ] as FunctionConfiguration[];
      vi.mocked(getLambdaFunctions).mockResolvedValue(functions);

      await scanLambdaFunctions();

      expect(pLimit).toHaveBeenCalledWith(1);
    });

    it("uses functions.length as concurrency when less than jobs", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 1000 },
      ] as FunctionConfiguration[];
      vi.mocked(getLambdaFunctions).mockResolvedValue(functions);

      await scanLambdaFunctions({ jobs: 4 });

      expect(pLimit).toHaveBeenCalledWith(2);
    });
  });
});
