import type { Lambda } from "@aws-sdk/client-lambda";
import { rm } from "node:fs/promises";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getLambdaFunctionScanOutput } from "./getLambdaFunctionScanOutput.ts";
import { downloadFile } from "./downloadFile.ts";
import { getLambdaFunctionContents } from "./getLambdaFunctionContents.ts";
import { hasSdkV2InBundle } from "./hasSdkV2InBundle.ts";

vi.mock("node:fs/promises");
vi.mock("./downloadFile.ts");
vi.mock("./getLambdaFunctionContents.ts");
vi.mock("./hasSdkV2InBundle.ts");

describe("getLambdaFunctionScanOutput", () => {
  const mockClient = { getFunction: vi.fn() } as unknown as Lambda;
  const functionName = "test-function";
  const region = "us-east-1";
  const runtime = "nodejs20.x";
  const sdkVersionRange = "2.x";
  const codeLocation = "https://example.com/function.zip";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns error when code location not found", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: {} });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Function Code location not found.",
    });
    expect(downloadFile).not.toHaveBeenCalled();
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });

  it("detects aws-sdk in package.json dependencies", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonFiles: [
        { path: "package.json", content: '{"dependencies":{"aws-sdk":"^2.0.0"}}' },
      ],
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: true,
      AwsSdkJsV2Location: "Defined in dependencies of 'package.json'",
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });

  it("checks bundle when package.json doesn't have aws-sdk in dependencies", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonFiles: [{ path: "package.json", content: '{"dependencies":{}}' }],
      bundleFile: { path: "index.js", content: "some bundle content" },
    });
    vi.mocked(hasSdkV2InBundle).mockReturnValue(true);

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: true,
      AwsSdkJsV2Location: "Bundled in 'index.js'",
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).toHaveBeenCalledWith("some bundle content", sdkVersionRange);
  });

  it("checks bundle when package.json has no dependencies key", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(downloadFile).mockResolvedValue(undefined);
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonFiles: [{ path: "package.json", content: "{}" }],
      bundleFile: { path: "index.js", content: "bundle" },
    });
    vi.mocked(hasSdkV2InBundle).mockReturnValue(true);

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result.ContainsAwsSdkJsV2).toBe(true);
    expect(result.AwsSdkJsV2Location).toBe("Bundled in 'index.js'");
  });

  it("returns false when aws-sdk not found", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonFiles: [{ path: "package.json", content: '{"dependencies":{}}' }],
      bundleFile: { path: "index.js", content: "some bundle content" },
    });
    vi.mocked(hasSdkV2InBundle).mockReturnValue(false);

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: false,
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).toHaveBeenCalledWith("some bundle content", sdkVersionRange);
  });

  it("returns false when no package.json and no bundle", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(downloadFile).mockResolvedValue(undefined);
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({});

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: false,
    });
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });

  it("returns error for invalid package.json", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonFiles: [{ path: "package.json", content: "invalid json" }],
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error:
        "Error parsing 'package.json': Unexpected token 'i', \"invalid json\" is not valid JSON",
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });

  it("returns error when download fails", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(downloadFile).mockRejectedValue(new Error("Download failed"));

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Error downloading or reading Lambda function code: Download failed",
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });

  it("returns error when download fails with non-Error", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(downloadFile).mockRejectedValue("string error");

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Error downloading or reading Lambda function code",
    });
  });

  it("skips aws-sdk version that does not satisfy range", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(downloadFile).mockResolvedValue(undefined);

    const sdkVersion = "2.1693.0";
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonFiles: [
        { path: "package.json", content: `{"dependencies":{"aws-sdk":"${sdkVersion}"}}` },
      ],
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange: `<${sdkVersion}`,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: `<${sdkVersion}`,
      ContainsAwsSdkJsV2: false,
    });
  });

  it("returns error when version satisfies check throws", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(downloadFile).mockResolvedValue(undefined);
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonFiles: [
        { path: "package.json", content: '{"dependencies":{"aws-sdk":"invalid"}}' },
      ],
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result.ContainsAwsSdkJsV2).toBeNull();
    expect(result.AwsSdkJsV2Error).toContain(
      "Error checking version range '2.x' for aws-sdk@invalid in 'package.json'",
    );
  });

  it("returns error when hasSdkV2InBundle throws", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(downloadFile).mockResolvedValue(undefined);
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      bundleFile: { path: "index.js", content: "bundle" },
    });
    vi.mocked(hasSdkV2InBundle).mockImplementation(() => {
      throw new Error("Bundle parse error");
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Error reading bundle 'index.js' for aws-sdk@2.x: Bundle parse error",
    });
  });

  it("returns error when hasSdkV2InBundle throws non-Error", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({ Code: { Location: codeLocation } });
    vi.mocked(downloadFile).mockResolvedValue(undefined);
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      bundleFile: { path: "index.js", content: "bundle" },
    });
    vi.mocked(hasSdkV2InBundle).mockImplementation(() => {
      throw "string error";
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      runtime,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdKVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Error reading bundle 'index.js' for aws-sdk@2.x",
    });
  });
});
