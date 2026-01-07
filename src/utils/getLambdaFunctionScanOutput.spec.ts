import { Lambda } from "@aws-sdk/client-lambda";
import { rm } from "node:fs/promises";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getLambdaFunctionScanOutput } from "./getLambdaFunctionScanOutput.ts";
import { downloadFile } from "./downloadFile.ts";
import { getLambdaFunctionContents } from "./getLambdaFunctionContents.ts";
import { hasSdkV2InFile } from "./hasSdkV2InFile.ts";
import { hasSdkV2InBundle } from "./hasSdkV2InBundle.ts";

vi.mock("node:fs/promises");
vi.mock("./downloadFile.ts");
vi.mock("./getLambdaFunctionContents.ts");
vi.mock("./hasSdkV2InFile.ts");
vi.mock("./hasSdkV2InBundle.ts");

describe("getLambdaFunctionScanOutput", () => {
  const mockClient = { getFunction: vi.fn() } as unknown as Lambda;
  const functionName = "test-function";
  const region = "us-east-1";
  const runtime = "nodejs20.x";
  const sdkVersionRange = "2.x";
  const codeLocation = "https://example.com/function.zip";

  const functionConfiguration = {
    Runtime: runtime,
    Handler: "index.handler",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(mockClient.getFunction).mockResolvedValue({
      Code: { Location: codeLocation },
      Configuration: functionConfiguration,
    });
    vi.mocked(downloadFile).mockResolvedValue(undefined);
    vi.mocked(hasSdkV2InFile).mockReturnValue(true);
    vi.mocked(hasSdkV2InBundle).mockReturnValue(false);
  });

  it("returns error when code location not found", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({
      Code: {},
      Configuration: functionConfiguration,
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Function Code location not found.",
    });
    expect(downloadFile).not.toHaveBeenCalled();
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
  });

  it("detects aws-sdk in handler bundle", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", "bundle content"]]),
    });
    vi.mocked(hasSdkV2InBundle).mockReturnValue(true);

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: true,
      AwsSdkJsV2Locations: ["index.js"],
    });
    expect(hasSdkV2InBundle).toHaveBeenCalledWith("bundle content", sdkVersionRange);
    expect(hasSdkV2InFile).not.toHaveBeenCalled();
  });

  it("detects aws-sdk in source code with exact version in package.json dependencies", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.mjs", 'import AWS from "aws-sdk";']]),
      packageJsonMap: new Map([["package.json", '{"dependencies":{"aws-sdk":"2.0.0"}}']]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: true,
      AwsSdkJsV2Locations: ["index.mjs"],
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
  });

  it("ignores aws-sdk in source code if exact version of SDK version can't be found", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.mjs", 'import AWS from "aws-sdk";']]),
      packageJsonMap: new Map([["package.json", '{"dependencies":{"aws-sdk":"^2.0.0"}}']]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: false,
    });
    expect(downloadFile).toHaveBeenCalledWith(codeLocation, expect.stringContaining(functionName));
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
  });

  it("returns false when aws-sdk not found in code", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", "no sdk here"]]),
      packageJsonMap: new Map([["package.json", '{"dependencies":{}}']]),
    });
    vi.mocked(hasSdkV2InFile).mockReturnValue(false);

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: false,
    });
  });

  it("returns false when no code files exist", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({ codeMap: new Map() });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: false,
    });
    expect(hasSdkV2InBundle).not.toHaveBeenCalled();
    expect(hasSdkV2InFile).not.toHaveBeenCalled();
  });

  it("returns false for invalid package.json", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", 'require("aws-sdk")']]),
      packageJsonMap: new Map([["package.json", "invalid json"]]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: false,
    });
  });

  it("returns error when download fails", async () => {
    vi.mocked(downloadFile).mockRejectedValue(new Error("Download failed"));

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Error downloading or reading Lambda function code: Download failed",
    });
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
  });

  it("returns error when download fails with non-Error", async () => {
    vi.mocked(downloadFile).mockRejectedValue("string error");

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: sdkVersionRange,
      ContainsAwsSdkJsV2: null,
      AwsSdkJsV2Error: "Error downloading or reading Lambda function code",
    });
  });

  it("skips aws-sdk version that does not satisfy range", async () => {
    const sdkVersion = "2.1693.0";
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", 'require("aws-sdk")']]),
      packageJsonMap: new Map([["package.json", `{"dependencies":{"aws-sdk":"${sdkVersion}"}}`]]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange: `<${sdkVersion}`,
    });

    expect(result).toEqual({
      FunctionName: functionName,
      Region: region,
      Runtime: runtime,
      SdkVersion: `<${sdkVersion}`,
      ContainsAwsSdkJsV2: false,
    });
  });

  it("returns false when version satisfies check throws", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", 'require("aws-sdk")']]),
      packageJsonMap: new Map([["package.json", '{"dependencies":{"aws-sdk":"invalid"}}']]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result.ContainsAwsSdkJsV2).toBe(false);
  });

  it("uses version from node_modules/aws-sdk/package.json when dependency is a range", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", 'require("aws-sdk")']]),
      packageJsonMap: new Map([["package.json", '{"dependencies":{"aws-sdk":"^2.0.0"}}']]),
      awsSdkPackageJsonMap: new Map([
        ["node_modules/aws-sdk/package.json", '{"version":"2.1692.0"}'],
      ]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      sdkVersionRange: ">=2.1692.0",
    });

    expect(result.ContainsAwsSdkJsV2).toBe(true);
  });

  it("uses version from node_modules/aws-sdk/package.json when package.json is not defined", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", 'require("aws-sdk")']]),
      awsSdkPackageJsonMap: new Map([
        ["node_modules/aws-sdk/package.json", '{"version":"2.1692.0"}'],
      ]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result.ContainsAwsSdkJsV2).toBe(true);
  });

  it("uses version from nested node_modules/aws-sdk/package.json", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["subdir/index.js", 'require("aws-sdk")']]),
      packageJsonMap: new Map([["subdir/package.json", '{"dependencies":{"aws-sdk":"^2.0.0"}}']]),
      awsSdkPackageJsonMap: new Map([
        ["subdir/node_modules/aws-sdk/package.json", '{"version":"2.1000.0"}'],
      ]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      sdkVersionRange: ">=2.1000.0",
    });

    expect(result.ContainsAwsSdkJsV2).toBe(true);
  });

  it("falls back to root node_modules when nested not found", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["subdir/index.js", 'require("aws-sdk")']]),
      packageJsonMap: new Map([["subdir/package.json", '{"dependencies":{"aws-sdk":"^2.0.0"}}']]),
      awsSdkPackageJsonMap: new Map([
        ["node_modules/aws-sdk/package.json", '{"version":"2.500.0"}'],
      ]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      sdkVersionRange: ">=2.500.0",
    });

    expect(result.ContainsAwsSdkJsV2).toBe(true);
  });

  it("ignores invalid aws-sdk package.json in node_modules if version in package.json dependencies is exact", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", 'require("aws-sdk")']]),
      packageJsonMap: new Map([["package.json", '{"dependencies":{"aws-sdk":"2.0.0"}}']]),
      awsSdkPackageJsonMap: new Map([["node_modules/aws-sdk/package.json", "invalid json"]]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result.ContainsAwsSdkJsV2).toBe(true);
  });

  it("returns false for invalid aws-sdk package.json in node_modules if version in package.json dependencies is not exact", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", 'require("aws-sdk")']]),
      packageJsonMap: new Map([["package.json", '{"dependencies":{"aws-sdk":"^2.0.0"}}']]),
      awsSdkPackageJsonMap: new Map([["node_modules/aws-sdk/package.json", "invalid json"]]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result.ContainsAwsSdkJsV2).toBe(false);
  });

  it("returns false when sdk found in code but not in package.json dependencies", async () => {
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["index.js", 'require("aws-sdk")']]),
      packageJsonMap: new Map([["package.json", '{"dependencies":{}}']]),
    });

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result.ContainsAwsSdkJsV2).toBe(false);
  });

  it("checks multiple handler file extensions", async () => {
    vi.mocked(mockClient.getFunction).mockResolvedValue({
      Code: { Location: codeLocation },
      Configuration: {
        ...functionConfiguration,
        Handler: "main.handler",
      },
    });
    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      codeMap: new Map([["main.mjs", "bundle content"]]),
    });
    vi.mocked(hasSdkV2InBundle).mockReturnValue(true);

    const result = await getLambdaFunctionScanOutput(mockClient, {
      functionName,
      region,
      sdkVersionRange,
    });

    expect(result.ContainsAwsSdkJsV2).toBe(true);
    expect(result.AwsSdkJsV2Locations).toEqual(["main.mjs"]);
  });
});
