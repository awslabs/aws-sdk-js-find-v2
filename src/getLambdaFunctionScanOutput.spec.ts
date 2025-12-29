import type { Lambda } from "@aws-sdk/client-lambda";
import { rm } from "node:fs/promises";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { JS_SDK_V2_MARKER } from "./constants.ts";
import { getLambdaFunctionScanOutput } from "./getLambdaFunctionScanOutput.ts";
import { downloadFile } from "./utils/downloadFile.ts";
import { getLambdaFunctionContents } from "./utils/getLambdaFunctionContents.ts";
import { hasSdkV2InBundle } from "./utils/hasSdkV2InBundle.ts";

vi.mock("node:fs/promises");
vi.mock("./utils/downloadFile.ts");
vi.mock("./utils/getLambdaFunctionContents.ts");
vi.mock("./utils/hasSdkV2InBundle.ts");

describe("getLambdaFunctionScanOutput", () => {
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
    await getLambdaFunctionScanOutput(mockClient, functionName);

    expect(console.log).toHaveBeenCalledWith(
      `${JS_SDK_V2_MARKER.UNKNOWN} ${functionName}: Code location not found.`,
    );
  });

  it("detects aws-sdk in package.json dependencies", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonContents: ['{"dependencies":{"aws-sdk":"^2.0.0"}}'],
    });

    await getLambdaFunctionScanOutput(mockClient, functionName);

    expect(downloadFile).toHaveBeenCalledWith(
      codeLocation,
      expect.stringMatching(new RegExp(functionName + ".zip$")),
    );
    expect(console.log).toHaveBeenCalledWith(`${JS_SDK_V2_MARKER.Y} ${functionName}`);
    expect(rm).toHaveBeenCalled();
  });

  it("detects aws-sdk in bundle content when not in package.json", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonContents: ['{"dependencies":{}}'],
      bundleContent: "some bundle content",
    });

    vi.mocked(hasSdkV2InBundle).mockReturnValue(true);

    await getLambdaFunctionScanOutput(mockClient, functionName);

    expect(hasSdkV2InBundle).toHaveBeenCalledWith("some bundle content");
    expect(console.log).toHaveBeenCalledWith(`${JS_SDK_V2_MARKER.Y} ${functionName}`);
  });

  it("logs N when aws-sdk not found", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonContents: ['{"dependencies":{}}'],
      bundleContent: "some bundle content",
    });

    vi.mocked(hasSdkV2InBundle).mockReturnValue(false);

    await getLambdaFunctionScanOutput(mockClient, functionName);

    expect(console.log).toHaveBeenCalledWith(`${JS_SDK_V2_MARKER.N} ${functionName}`);
  });

  it("handles invalid package.json gracefully", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    vi.mocked(getLambdaFunctionContents).mockResolvedValue({
      packageJsonContents: ["invalid json"],
      bundleContent: "some bundle content",
    });

    vi.mocked(hasSdkV2InBundle).mockReturnValue(false);

    await getLambdaFunctionScanOutput(mockClient, functionName);

    expect(console.log).toHaveBeenCalledWith(`${JS_SDK_V2_MARKER.N} ${functionName}`);
  });

  it("cleans up zip file even when error occurs", async () => {
    mockClient.getFunction = vi.fn().mockResolvedValue({
      Code: { Location: codeLocation },
    });

    vi.mocked(downloadFile).mockRejectedValue(new Error("Download failed"));

    await expect(getLambdaFunctionScanOutput(mockClient, functionName)).rejects.toThrow(
      "Download failed",
    );
    expect(rm).toHaveBeenCalledWith(expect.stringContaining(`${functionName}.zip`), {
      force: true,
    });
  });
});
