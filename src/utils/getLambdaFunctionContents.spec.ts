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
  const mockCode = "code content";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns empty codeMap when zip entries can't be read", async () => {
    mockZip.entries.mockRejectedValue(new Error("zip entries error"));
    const result = await getLambdaFunctionContents(mockZipPath);

    expect(result).toEqual({ codeMap: {} });
    expect(mockZip.entryData).not.toHaveBeenCalled();
    expect(mockZip.close).toHaveBeenCalled();
  });

  describe("returns empty codeMap when entry data can't be read", () => {
    it("with only package.json", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: true },
      });
      mockZip.entryData.mockRejectedValue(new Error("zip entry data error"));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ codeMap: {} });
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

      expect(result).toEqual({ codeMap: {} });
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

      expect(result).toEqual({ codeMap: {} });
      expect(mockZip.entryData).toHaveBeenCalledTimes(2);
      expect(mockZip.entryData).toHaveBeenNthCalledWith(1, "package.json");
      expect(mockZip.entryData).toHaveBeenNthCalledWith(2, "index.js");
      expect(mockZip.close).toHaveBeenCalled();
    });
  });

  describe("when package.json present", () => {
    it("returns packageJsonMap", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: true },
        "index.js": { name: "index.js", isFile: true },
      });
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJson));
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockCode));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        codeMap: { "index.js": mockCode },
        packageJsonMap: { "package.json": mockPackageJson },
      });
      expect(mockZip.entryData).toHaveBeenCalledTimes(2);
      expect(mockZip.entryData).toHaveBeenNthCalledWith(1, "package.json");
      expect(mockZip.entryData).toHaveBeenNthCalledWith(2, "index.js");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("skips node_modules directory", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: true },
        "node_modules/package.json": { name: "node_modules/package.json", isFile: true },
      });
      mockZip.entryData.mockResolvedValue(Buffer.from(mockPackageJson));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        codeMap: {},
        packageJsonMap: { "package.json": mockPackageJson },
      });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("package.json");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("skips package.json directory", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: false },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ codeMap: {} });
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
        "packages/app/package.json": { name: "packages/app/package.json", isFile: true },
      });
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJsons.root));
      mockZip.entryData.mockResolvedValueOnce(Buffer.from(mockPackageJsons.app));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        codeMap: {},
        packageJsonMap: {
          "package.json": mockPackageJsons.root,
          "packages/app/package.json": mockPackageJsons.app,
        },
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
        codeMap: {},
        packageJsonMap: { "package.json": mockPackageJson },
        awsSdkPackageJsonMap: { "node_modules/aws-sdk/package.json": awsSdkPackageJson },
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
        codeMap: {},
        packageJsonMap: { "package.json": mockPackageJson },
        awsSdkPackageJsonMap: {
          "packages/app/node_modules/aws-sdk/package.json": awsSdkPackageJson,
        },
      });
    });
  });

  describe("code files", () => {
    it("returns codeMap for .js files", async () => {
      mockZip.entries.mockResolvedValue({
        "index.js": { name: "index.js", isFile: true },
      });
      mockZip.entryData.mockResolvedValue(Buffer.from(mockCode));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ codeMap: { "index.js": mockCode } });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.js");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("returns codeMap for .mjs files", async () => {
      mockZip.entries.mockResolvedValue({
        "index.mjs": { name: "index.mjs", isFile: true },
      });
      mockZip.entryData.mockResolvedValue(Buffer.from(mockCode));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ codeMap: { "index.mjs": mockCode } });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.mjs");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("returns codeMap for .cjs files", async () => {
      mockZip.entries.mockResolvedValue({
        "index.cjs": { name: "index.cjs", isFile: true },
      });
      mockZip.entryData.mockResolvedValue(Buffer.from(mockCode));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ codeMap: { "index.cjs": mockCode } });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.cjs");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("returns codeMap for .ts files", async () => {
      mockZip.entries.mockResolvedValue({
        "index.ts": { name: "index.ts", isFile: true },
      });
      mockZip.entryData.mockResolvedValue(Buffer.from(mockCode));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ codeMap: { "index.ts": mockCode } });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.ts");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("returns codeMap with multiple code files", async () => {
      mockZip.entries.mockResolvedValue({
        "index.js": { name: "index.js", isFile: true },
        "utils.js": { name: "utils.js", isFile: true },
      });
      mockZip.entryData.mockResolvedValue(Buffer.from(mockCode));

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        codeMap: { "index.js": mockCode, "utils.js": mockCode },
      });
      expect(mockZip.entryData).toHaveBeenCalledTimes(2);
      expect(mockZip.entryData).toHaveBeenNthCalledWith(1, "index.js");
      expect(mockZip.entryData).toHaveBeenNthCalledWith(2, "utils.js");
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("skips non-file entries", async () => {
      mockZip.entries.mockResolvedValue({
        "index.js": { name: "index.js", isFile: false },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ codeMap: {} });
      expect(mockZip.entryData).not.toHaveBeenCalled();
      expect(mockZip.close).toHaveBeenCalled();
    });

    it("skips non-code files", async () => {
      mockZip.entries.mockResolvedValue({
        "readme.md": { name: "readme.md", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ codeMap: {} });
      expect(mockZip.entryData).not.toHaveBeenCalled();
      expect(mockZip.close).toHaveBeenCalled();
    });
  });
});
