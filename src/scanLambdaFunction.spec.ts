import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Lambda } from "@aws-sdk/client-lambda";

// oxlint-disable-next-line sort-imports
import { JS_SDK_V2_MARKER } from "./constants.ts";
import { scanLambdaFunction } from "./scanLambdaFunction.ts";

vi.mock("./utils/downloadFile.ts");
vi.mock("./utils/getLambdaFunctionContents.ts");
vi.mock("./utils/hasSdkV2InBundle.ts");
vi.mock("node:fs/promises");

const mockDownloadFile = vi.hoisted(() => vi.fn());
const mockGetLambdaFunctionContents = vi.hoisted(() => vi.fn());
const mockHasSdkV2InBundle = vi.hoisted(() => vi.fn());
const mockRm = vi.hoisted(() => vi.fn());

vi.mock("./utils/downloadFile.ts", () => ({
  downloadFile: mockDownloadFile,
}));

vi.mock("./utils/getLambdaFunctionContents.ts", () => ({
  getLambdaFunctionContents: mockGetLambdaFunctionContents,
}));

vi.mock("./utils/hasSdkV2InBundle.ts", () => ({
  hasSdkV2InBundle: mockHasSdkV2InBundle,
}));

vi.mock("node:fs/promises", () => ({
  rm: mockRm,
}));

describe(scanLambdaFunction.name, () => {
  const mockClient = {
    getFunction: vi.fn(),
  } as unknown as Lambda;

  const functionName = "test-function";
  const codeLocation = "https://example.com/function.zip";

  beforeEach(() => {
    vi.clearAllMocks();
    console.log = vi.fn();
  });

  it("logs unknown when code location not found", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({ Code: {} });
    await scanLambdaFunction(mockClient, functionName);

    expect(console.log).toHaveBeenCalledWith(
      `${JS_SDK_V2_MARKER.UNKNOWN} ${functionName}: Code location not found.`,
    );
  });

  it("detects aws-sdk in package.json dependencies", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    mockGetLambdaFunctionContents.mockResolvedValue({
      packageJsonContents: ['{"dependencies":{"aws-sdk":"^2.0.0"}}'],
      bundleContent: null,
    });

    await scanLambdaFunction(mockClient, functionName);

    expect(mockDownloadFile).toHaveBeenCalledWith(
      codeLocation,
      expect.stringMatching(new RegExp(functionName + ".zip$")),
    );
    expect(console.log).toHaveBeenCalledWith(`${JS_SDK_V2_MARKER.Y} ${functionName}`);
    expect(mockRm).toHaveBeenCalled();
  });

  it("detects aws-sdk in bundle content when not in package.json", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    mockGetLambdaFunctionContents.mockResolvedValue({
      packageJsonContents: ['{"dependencies":{}}'],
      bundleContent: "some bundle content",
    });

    mockHasSdkV2InBundle.mockReturnValue(true);

    await scanLambdaFunction(mockClient, functionName);

    expect(mockHasSdkV2InBundle).toHaveBeenCalledWith("some bundle content");
    expect(console.log).toHaveBeenCalledWith(`${JS_SDK_V2_MARKER.Y} ${functionName}`);
  });

  it("logs N when aws-sdk not found", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    mockGetLambdaFunctionContents.mockResolvedValue({
      packageJsonContents: ['{"dependencies":{}}'],
      bundleContent: "some bundle content",
    });

    mockHasSdkV2InBundle.mockReturnValue(false);

    await scanLambdaFunction(mockClient, functionName);

    expect(console.log).toHaveBeenCalledWith(`${JS_SDK_V2_MARKER.N} ${functionName}`);
  });

  it("handles invalid package.json gracefully", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    mockGetLambdaFunctionContents.mockResolvedValue({
      packageJsonContents: ["invalid json"],
      bundleContent: "some bundle content",
    });

    mockHasSdkV2InBundle.mockReturnValue(false);

    await scanLambdaFunction(mockClient, functionName);

    expect(console.log).toHaveBeenCalledWith(`${JS_SDK_V2_MARKER.N} ${functionName}`);
  });

  it("cleans up zip file even when error occurs", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    mockDownloadFile.mockRejectedValue(new Error("Download failed"));

    await expect(scanLambdaFunction(mockClient, functionName)).rejects.toThrow("Download failed");
    expect(mockRm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
  });
});
