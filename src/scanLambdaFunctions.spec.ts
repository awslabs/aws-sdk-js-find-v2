import { describe, it, expect, vi, beforeEach } from "vitest";
import { scanLambdaFunctions } from "./scanLambdaFunctions.ts";
import { JS_SDK_V2_MARKER } from "./constants.ts";

vi.mock("@aws-sdk/client-lambda");
vi.mock("./scanLambdaFunction.ts");
vi.mock("./utils/getDownloadConfirmation.ts");
vi.mock("node:os");
vi.mock("p-limit");

const mockPaginateListFunctions = vi.hoisted(() => vi.fn());
const mockScanLambdaFunction = vi.hoisted(() => vi.fn());
const mockLambdaConstructor = vi.hoisted(() => vi.fn());
const mockCpus = vi.hoisted(() => vi.fn());
const mockPLimit = vi.hoisted(() => vi.fn());
const mockGetDownloadConfirmation = vi.hoisted(() => vi.fn());

vi.mock("@aws-sdk/client-lambda", () => ({
  Lambda: class {
    constructor(config?: any) {
      mockLambdaConstructor(config);
    }
    config = {
      region: vi.fn().mockResolvedValue("us-east-1"),
    };
  },
  paginateListFunctions: mockPaginateListFunctions,
}));

vi.mock("./scanLambdaFunction.ts", () => ({
  scanLambdaFunction: mockScanLambdaFunction,
}));

vi.mock("./utils/getDownloadConfirmation.ts", () => ({
  getDownloadConfirmation: mockGetDownloadConfirmation,
}));

vi.mock("node:os", () => ({
  cpus: mockCpus,
}));

vi.mock("p-limit", () => ({
  default: mockPLimit,
}));

describe(scanLambdaFunctions.name, () => {
  beforeEach(() => {
    vi.clearAllMocks();
    console.log = vi.fn();
    process.exit = vi.fn() as any;
    mockCpus.mockReturnValue([{}, {}, {}, {}]); // 4 CPUs by default
    mockPLimit.mockImplementation(() => (fn: () => Promise<void>) => fn());
    mockGetDownloadConfirmation.mockResolvedValue(true);
  });

  it("exits early when no functions found", async () => {
    mockPaginateListFunctions.mockReturnValue([{ Functions: [] }]);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith("No functions found.");
    expect(process.exit).toHaveBeenCalledWith(0);
  });

  it("filters and scans only Node.js functions", async () => {
    const functions = [
      { FunctionName: "node-fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
      { FunctionName: "python-fn", Runtime: "python3.9", CodeSize: 1000 },
      { FunctionName: "node-fn-2", Runtime: "nodejs20.x", CodeSize: 1000 },
      { FunctionName: "java-fn", Runtime: "java11", CodeSize: 1000 },
    ];

    mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith('Reading 2 functions from "us-east-1" region.');
    expect(mockScanLambdaFunction).toHaveBeenCalledTimes(2);
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "node-fn-1");
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "node-fn-2");
  });

  it("handles functions without names", async () => {
    const functions = [
      { FunctionName: "valid-fn", Runtime: "nodejs18.x", CodeSize: 1000 },
      { Runtime: "nodejs18.x", CodeSize: 1000 }, // No FunctionName
      { FunctionName: undefined, Runtime: "nodejs18.x", CodeSize: 1000 },
    ];

    mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

    await scanLambdaFunctions();

    expect(mockScanLambdaFunction).toHaveBeenCalledTimes(1);
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "valid-fn");
  });

  it("processes multiple pages of functions", async () => {
    const page1 = { Functions: [{ FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 }] };
    const page2 = { Functions: [{ FunctionName: "fn-2", Runtime: "nodejs20.x", CodeSize: 1000 }] };

    mockPaginateListFunctions.mockReturnValue([page1, page2]);

    await scanLambdaFunctions();

    expect(mockScanLambdaFunction).toHaveBeenCalledTimes(2);
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "fn-1");
    expect(mockScanLambdaFunction).toHaveBeenCalledWith(expect.any(Object), "fn-2");
  });

  it("displays correct output messages", async () => {
    const functions = [{ FunctionName: "test-fn", Runtime: "nodejs18.x", CodeSize: 1000 }];
    mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

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
    mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

    await scanLambdaFunctions();

    expect(console.log).toHaveBeenCalledWith('Reading 2 functions from "us-east-1" region.');
  });

  it("creates Lambda client with specified region", async () => {
    mockPaginateListFunctions.mockReturnValue([{ Functions: [] }]);

    await scanLambdaFunctions({ region: "us-west-2" });

    expect(mockLambdaConstructor).toHaveBeenCalledWith({ region: "us-west-2" });
  });

  it("creates Lambda client with undefined region when not specified", async () => {
    mockPaginateListFunctions.mockReturnValue([{ Functions: [] }]);

    await scanLambdaFunctions();

    expect(mockLambdaConstructor).toHaveBeenCalledWith({ region: undefined });
  });

  describe("download confirmation", () => {
    it("prompts for confirmation when yes is not set", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 2000 },
      ];
      mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

      await scanLambdaFunctions();

      expect(mockGetDownloadConfirmation).toHaveBeenCalledWith(2, 3000);
    });

    it("skips confirmation when yes is true", async () => {
      const functions = [{ FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 }];
      mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

      await scanLambdaFunctions({ yes: true });

      expect(mockGetDownloadConfirmation).not.toHaveBeenCalled();
    });

    it("exits when confirmation is declined", async () => {
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 4000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 5000 },
      ];
      mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);
      mockGetDownloadConfirmation.mockResolvedValue(false);

      await scanLambdaFunctions();

      expect(mockGetDownloadConfirmation).toHaveBeenCalledWith(2, 9000);
      expect(console.log).toHaveBeenCalledWith("Exiting.");
      expect(process.exit).toHaveBeenCalledWith(0);
    });
  });

  describe("concurrency with p-limit", () => {
    it("uses CPU count as concurrency when it's less than functions.length", async () => {
      mockCpus.mockReturnValue([{}, {}]); // 2 CPUs
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-3", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-4", Runtime: "nodejs18.x", CodeSize: 1000 },
      ];
      mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

      await scanLambdaFunctions();

      expect(mockPLimit).toHaveBeenCalledWith(2);
    });

    it("uses concurrency of 1 when CPU count is not available", async () => {
      mockCpus.mockReturnValue([]);
      const functions = [{ FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 }];
      mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

      await scanLambdaFunctions();

      expect(mockPLimit).toHaveBeenCalledWith(1);
    });

    it("uses functions.length as concurrency when less than CPU count", async () => {
      mockCpus.mockReturnValue([{}, {}, {}, {}]); // 4 CPUs
      const functions = [
        { FunctionName: "fn-1", Runtime: "nodejs18.x", CodeSize: 1000 },
        { FunctionName: "fn-2", Runtime: "nodejs18.x", CodeSize: 1000 },
      ];
      mockPaginateListFunctions.mockReturnValue([{ Functions: functions }]);

      await scanLambdaFunctions();

      expect(mockPLimit).toHaveBeenCalledWith(2);
    });
  });
});
