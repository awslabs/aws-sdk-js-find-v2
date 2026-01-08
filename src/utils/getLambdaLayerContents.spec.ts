import { describe, it, expect, vi, beforeEach } from "vitest";
import { getLambdaLayerContents } from "./getLambdaLayerContents.ts";
import { processRemoteZip } from "./processRemoteZip.ts";
import { processZipEntries } from "./processZipEntries.ts";

vi.mock("./processRemoteZip.ts");
vi.mock("./processZipEntries.ts");

describe("getLambdaLayerContents", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns empty map when no aws-sdk package.json found", async () => {
    vi.mocked(processRemoteZip).mockImplementation(async (url, callback) => {
      await callback("/tmp/test.zip");
    });
    vi.mocked(processZipEntries).mockImplementation(async (zipPath, callback) => {
      // No entries processed
    });

    const result = await getLambdaLayerContents("https://example.com/layer.zip");

    expect(result).toBeInstanceOf(Map);
    expect(result.size).toBe(0);
  });

  it("extracts aws-sdk version from package.json", async () => {
    const mockEntry = {
      isFile: true,
      name: "node_modules/aws-sdk/package.json",
    };
    const mockGetData = vi
      .fn()
      .mockResolvedValue(Buffer.from(JSON.stringify({ version: "2.1234.0" })));

    vi.mocked(processRemoteZip).mockImplementation(async (url, callback) => {
      await callback("/tmp/test.zip");
    });
    vi.mocked(processZipEntries).mockImplementation(async (zipPath, callback) => {
      await callback(mockEntry, mockGetData);
    });

    const result = await getLambdaLayerContents("https://example.com/layer.zip");

    expect(result.size).toBe(1);
    expect(result.get("node_modules/aws-sdk/package.json")).toEqual({ version: "2.1234.0" });
  });

  it("ignores non-file entries", async () => {
    const mockEntry = {
      isFile: false,
      name: "node_modules/aws-sdk/package.json",
    };

    vi.mocked(processRemoteZip).mockImplementation(async (url, callback) => {
      await callback("/tmp/test.zip");
    });
    vi.mocked(processZipEntries).mockImplementation(async (zipPath, callback) => {
      await callback(mockEntry, vi.fn());
    });

    const result = await getLambdaLayerContents("https://example.com/layer.zip");

    expect(result.size).toBe(0);
  });

  it("ignores files not ending with aws-sdk package.json", async () => {
    const mockEntry = {
      isFile: true,
      name: "some-other-file.json",
    };

    vi.mocked(processRemoteZip).mockImplementation(async (url, callback) => {
      await callback("/tmp/test.zip");
    });
    vi.mocked(processZipEntries).mockImplementation(async (zipPath, callback) => {
      await callback(mockEntry, vi.fn());
    });

    const result = await getLambdaLayerContents("https://example.com/layer.zip");

    expect(result.size).toBe(0);
  });

  it("handles JSON parse errors gracefully", async () => {
    const mockEntry = {
      isFile: true,
      name: "node_modules/aws-sdk/package.json",
    };
    const mockGetData = vi.fn().mockResolvedValue(Buffer.from("invalid json"));

    vi.mocked(processRemoteZip).mockImplementation(async (url, callback) => {
      await callback("/tmp/test.zip");
    });
    vi.mocked(processZipEntries).mockImplementation(async (zipPath, callback) => {
      await callback(mockEntry, mockGetData);
    });

    const result = await getLambdaLayerContents("https://example.com/layer.zip");

    expect(result.size).toBe(0);
  });

  it("handles getData errors gracefully", async () => {
    const mockEntry = {
      isFile: true,
      name: "node_modules/aws-sdk/package.json",
    };
    const mockGetData = vi.fn().mockRejectedValue(new Error("Read error"));

    vi.mocked(processRemoteZip).mockImplementation(async (url, callback) => {
      await callback("/tmp/test.zip");
    });
    vi.mocked(processZipEntries).mockImplementation(async (zipPath, callback) => {
      await callback(mockEntry, mockGetData);
    });

    const result = await getLambdaLayerContents("https://example.com/layer.zip");

    expect(result.size).toBe(0);
  });
});
