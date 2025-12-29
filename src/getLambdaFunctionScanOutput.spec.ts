import type { Lambda } from "@aws-sdk/client-lambda";
import { rm } from "node:fs/promises";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getLambdaFunctionScanOutput } from "./getLambdaFunctionScanOutput.ts";
import { downloadFile } from "./utils/downloadFile.ts";
import { getLambdaFunctionContents } from "./utils/getLambdaFunctionContents.ts";
import { hasSdkV2InBundle } from "./utils/hasSdkV2InBundle.ts";

vi.mock("node:fs/promises");
vi.mock("./utils/downloadFile.ts");
vi.mock("./utils/getLambdaFunctionContents.ts");
vi.mock("./utils/hasSdkV2InBundle.ts");

describe("getLambdaFunctionScanOutput", () => {
  const mockClient = { getFunction: vi.fn() } as unknown as Lambda;
  const functionName = "test-function";
  const region = "us-east-1";
  const codeLocation = "https://example.com/function.zip";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns error when code location not found", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: {} });

    const result = await getLambdaFunctionScanOutput(mockClient, { functionName, region });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Function Code location not found.",
    });
    expect(downloadFile).not.toHaveBeenCalled();
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });

  it("detects aws-sdk in package.json dependencies", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonContents: ['{"dependencies":{"aws-sdk":"^2.0.0"}}'],
    });

    const result = await getLambdaFunctionScanOutput(mockClient, { functionName, region });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      ContainsAwsSdkJsV2: true,
      AwsSdkJsV2Location: "Defined in package.json dependencies.",
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });

  it("detects aws-sdk in bundle content when not in package.json", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonContents: ['{"dependencies":{}}'],
      bundleContent: "some bundle content",
    });
    vi.mocked(hasSdkV2InBundle).mockReturnValue(true);

    const result = await getLambdaFunctionScanOutput(mockClient, { functionName, region });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      ContainsAwsSdkJsV2: true,
      AwsSdkJsV2Location: "Bundled in index file.",
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).toHaveBeenCalledWith("some bundle content");
  });

  it("returns false when aws-sdk not found", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonContents: ['{"dependencies":{}}'],
      bundleContent: "some bundle content",
    });
    vi.mocked(hasSdkV2InBundle).mockReturnValue(false);

    const result = await getLambdaFunctionScanOutput(mockClient, { functionName, region });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      ContainsAwsSdkJsV2: false,
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).toHaveBeenCalledWith("some bundle content");
  });

  it("returns error for invalid package.json", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonContents: ["invalid json"],
    });

    const result = await getLambdaFunctionScanOutput(mockClient, { functionName, region });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Error parsing package.json.",
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });

  it("cleans up zip file even when error occurs", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(downloadFile).mockRejectedValue(new Error("Download failed"));

    await expect(getLambdaFunctionScanOutput(mockClient, { functionName, region })).rejects.toThrow(
      "Download failed",
    );
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });
});
