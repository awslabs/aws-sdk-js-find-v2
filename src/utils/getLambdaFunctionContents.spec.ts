import { beforeEach, describe, it, expect, vi } from "vitest";
import { getLambdaFunctionContents } from "./getLambdaFunctionContents.ts";

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

describe("getLambdaFunctionContents", () => {
  const mockZipPath = "/path/to/file.zip";
  const mockPackageJson = '{"name":"test"}';
  const mockBundle = "bundle content";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns empty object when zip entries can't be read", async () => {
    mockZip.entries.mockRejectedValue(new Error("zip entries error"));
    const result = await getLambdaFunctionContents(mockZipPath);

    expect(result).toEqual({});
    expect(mockZip.entryData).not.toHaveBeenCalled();
    expect(mockZip.close).toHaveBeenCalled();
  });

  describe("returns empty object when entry data can't be read", () => {
    it("with only package.json", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: true },
      });
      mockZip.entryData.mockRejectedValue(new Error("zip entry data error"));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("package.json");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("with only index.js", async () => {
      mockZip.entries.mockResolvedValue({
        "index.js": { name: "index.js", isFile: true },
      });
      mockZip.entryData.mockRejectedValue(new Error("zip entry data error"));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.js");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("with both package.json and index.js", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: true },
        "index.js": { name: "index.js", isFile: true },
      });
      mockZip.entryData.mockRejectedValue(new Error("zip entry data error"));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockZip.entryData).toHaveBeenCalledTimes(2);
      expect(mockZip.entryData).toHaveBeenNthCalledWith(1, "package.json");
      expect(mockZip.entryData).toHaveBeenNthCalledWith(2, "index.js");
      expect(mockZip.close).toHaveBeenCalled();
    });
  });

  describe("when package.json present", () => {
    beforeEach(() => {
      mockZip.entryData.mockResolvedValue(Buffer.from(mockPackageJson));
    });

    it("returns packageJsonFiles from package.json", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: true },
        "index.js": { name: "index.js", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        packageJsonFiles: [{ path: "package.json", content: mockPackageJson }],
        awsSdkPackageJsonMap: {},
      });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("package.json");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("skips node_modules directory", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: true },
        "node_modules/package.json": {
          name: "node_modules/package.json",
          isFile: true,
        },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        packageJsonFiles: [{ path: "package.json", content: mockPackageJson }],
        awsSdkPackageJsonMap: {},
      });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("package.json");
      expect(mockZip.entryData).not.toHaveBeenCalledWith("node_modules/package.json");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("skips package.json directory", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: false },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockZip.entryData).not.toHaveBeenCalled();
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("returns multiple package.json files", async () => {
      const mockPackageJsons = {
        root: '{"name":"root"}',
        app: '{"name":"app"}',
      };
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: true },
        "packages/app/package.json": {
          name: "packages/app/package.json",
          isFile: true,
        },
      });
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJsons.root));
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJsons.app));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        packageJsonFiles: [
          { path: "package.json", content: mockPackageJsons.root },
          { path: "packages/app/package.json", content: mockPackageJsons.app },
        ],
        awsSdkPackageJsonMap: {},
      });
      expect(mockZip.entryData).toHaveBeenCalledTimes(2);
      expect(mockZip.entryData).toHaveBeenNthCalledWith(1, "package.json");
      expect(mockZip.entryData).toHaveBeenNthCalledWith(2, "packages/app/package.json");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("populates awsSdkPackageJsonMap for aws-sdk package.json", async () => {
      const awsSdkPackageJson = '{"name":"aws-sdk","version":"2.1692.0"}';
      mockZip.entries.mockResolvedValue({
        "node_modules/aws-sdk/package.json": {
          name: "node_modules/aws-sdk/package.json",
          isFile: true,
        },
        "package.json": { name: "package.json", isFile: true },
      });
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(awsSdkPackageJson));
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJson));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        packageJsonFiles: [{ path: "package.json", content: mockPackageJson }],
        awsSdkPackageJsonMap: {
          "node_modules/aws-sdk/package.json": awsSdkPackageJson,
        },
      });
    });

    it("populates awsSdkPackageJsonMap for nested aws-sdk package.json", async () => {
      const awsSdkPackageJson = '{"name":"aws-sdk","version":"2.1692.0"}';
      mockZip.entries.mockResolvedValue({
        "packages/app/node_modules/aws-sdk/package.json": {
          name: "packages/app/node_modules/aws-sdk/package.json",
          isFile: true,
        },
        "package.json": { name: "package.json", isFile: true },
      });
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(awsSdkPackageJson));
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJson));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        packageJsonFiles: [{ path: "package.json", content: mockPackageJson }],
        awsSdkPackageJsonMap: {
          "packages/app/node_modules/aws-sdk/package.json": awsSdkPackageJson,
        },
      });
    });
  });

  describe("when package.json not present", () => {
    beforeEach(() => {
      mockZip.entryData.mockResolvedValue(Buffer.from(mockBundle));
    });

    it("returns bundleFile for index.js file, if present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.js": { name: "index.js", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleFile: { path: "index.js", content: mockBundle } });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.js");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("returns bundleFile for index.mjs file when index.js not present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.mjs": { name: "index.mjs", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleFile: { path: "index.mjs", content: mockBundle } });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.mjs");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("returns bundleFile for index.cjs file when index.js/mjs not present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.cjs": { name: "index.cjs", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleFile: { path: "index.cjs", content: mockBundle } });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.cjs");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("prefers index.js over index.mjs/cjs when all are present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.js": { name: "index.js", isFile: true },
        "index.mjs": { name: "index.mjs", isFile: true },
        "index.cjs": { name: "index.cjs", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleFile: { path: "index.js", content: mockBundle } });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.js");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("prefers index.mjs over index.cjs when both are present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.mjs": { name: "index.mjs", isFile: true },
        "index.cjs": { name: "index.cjs", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleFile: { path: "index.mjs", content: mockBundle } });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.mjs");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("skips index.js/mjs/cjs if they're not files", async () => {
      mockZip.entries.mockResolvedValue({
        "index.js": { name: "index.js", isFile: false },
        "index.mjs": { name: "index.mjs", isFile: false },
        "index.cjs": { name: "index.cjs", isFile: false },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockZip.entryData).not.toHaveBeenCalled();
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("returns empty object when no package.json or index.js/mjs/cjs", async () => {
      mockZip.entries.mockResolvedValue({
        "other.js": { name: "other.js", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockZip.entryData).not.toHaveBeenCalled();
      expect(mockZip.close).toHaveBeenCalled();
    });
  });
});
