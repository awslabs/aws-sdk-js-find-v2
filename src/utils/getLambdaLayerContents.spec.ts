import { beforeEach, describe, it, expect, vi } from "vitest";
import { getLambdaLayerContents } from "./getLambdaLayerContents.ts";

const mockZip = {
  entries: vi.fn(),
  entryData: vi.fn(),
  close: vi.fn(),
};

vi.mock("node-stream-zip", () => ({
  default: {
    async: class {
      entries = mockZip.entries;
      entryData = mockZip.entryData;
      close = mockZip.close;
    },
  },
}));

describe("getLambdaLayerContents", () => {
  const mockZipPath = "/path/to/layer.zip";
  const mockPackageJson = '{"name":"aws-sdk","version":"2.1692.0"}';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns empty map when zip entries can't be read", async () => {
    mockZip.entries.mockRejectedValue(new Error("zip entries error"));
    const result = await getLambdaLayerContents(mockZipPath);

    expect(result).toEqual(new Map());
    expect(mockZip.entryData).not.toHaveBeenCalled();
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("returns empty map when entry data can't be read", async () => {
    mockZip.entries.mockResolvedValue({
      "nodejs/node_modules/aws-sdk/package.json": {
        name: "nodejs/node_modules/aws-sdk/package.json",
        isFile: true,
      },
    });
    mockZip.entryData.mockRejectedValue(new Error("zip entry data error"));

    const result = await getLambdaLayerContents(mockZipPath);

    expect(result).toEqual(new Map());
    expect(mockZip.entryData).toHaveBeenCalledOnce();
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("skips non-file entries", async () => {
    mockZip.entries.mockResolvedValue({
      "nodejs/node_modules/aws-sdk/package.json": {
        name: "nodejs/node_modules/aws-sdk/package.json",
        isFile: false,
      },
    });

    const result = await getLambdaLayerContents(mockZipPath);

    expect(result).toEqual(new Map());
    expect(mockZip.entryData).not.toHaveBeenCalled();
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("skips files not ending with node_modules/aws-sdk/package.json", async () => {
    mockZip.entries.mockResolvedValue({
      "nodejs/node_modules/other/package.json": {
        name: "nodejs/node_modules/other/package.json",
        isFile: true,
      },
    });

    const result = await getLambdaLayerContents(mockZipPath);

    expect(result).toEqual(new Map());
    expect(mockZip.entryData).not.toHaveBeenCalled();
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("returns aws-sdk package.json content", async () => {
    mockZip.entries.mockResolvedValue({
      "nodejs/node_modules/aws-sdk/package.json": {
        name: "nodejs/node_modules/aws-sdk/package.json",
        isFile: true,
      },
    });
    mockZip.entryData.mockResolvedValue(Buffer.from(mockPackageJson));

    const result = await getLambdaLayerContents(mockZipPath);

    expect(result).toEqual(
      new Map([["nodejs/node_modules/aws-sdk/package.json", mockPackageJson]]),
    );
    expect(mockZip.entryData).toHaveBeenCalledWith("nodejs/node_modules/aws-sdk/package.json");
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("returns multiple aws-sdk package.json files", async () => {
    const mockPackageJson2 = '{"name":"aws-sdk","version":"2.1000.0"}';
    const mockPackageJson3 = '{"name":"aws-sdk","version":"2.500.0"}';
    mockZip.entries.mockResolvedValue({
      "node_modules/aws-sdk/package.json": {
        name: "node_modules/aws-sdk/package.json",
        isFile: true,
      },
      "nodejs/node_modules/aws-sdk/package.json": {
        name: "nodejs/node_modules/aws-sdk/package.json",
        isFile: true,
      },
      "nodejs/node24/node_modules/aws-sdk/package.json": {
        name: "nodejs/node24/node_modules/aws-sdk/package.json",
        isFile: true,
      },
    });
    mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJson));
    mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJson2));
    mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJson3));

    const result = await getLambdaLayerContents(mockZipPath);

    expect(result).toEqual(
      new Map([
        ["node_modules/aws-sdk/package.json", mockPackageJson],
        ["nodejs/node_modules/aws-sdk/package.json", mockPackageJson2],
        ["nodejs/node24/node_modules/aws-sdk/package.json", mockPackageJson3],
      ]),
    );
    expect(mockZip.entryData).toHaveBeenCalledTimes(3);
    expect(mockZip.close).toHaveBeenCalled();
  });
});
