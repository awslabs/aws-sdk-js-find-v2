import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
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

describe(getLambdaFunctionContents.name, () => {
  const mockZipPath = "/path/to/file.zip";
  const mockPackageJson = '{"name":"test"}';
  const mockBundle = "bundle content";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("returns empty object when zip entries can't be read", async () => {
    mockZip.entries.mockRejectedValue(new Error("zip entries error"));
    const result = await getLambdaFunctionContents(mockZipPath);

    expect(result).toEqual({});
    expect(mockZip.entryData).not.toHaveBeenCalled();
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
    });
  });

  describe("when package.json present", () => {
    beforeEach(() => {
      mockZip.entryData.mockResolvedValue(Buffer.from(mockPackageJson));
    });

    it("returns packageJsonContents from package.json", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: true },
        "index.js": { name: "index.js", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ packageJsonContents: [mockPackageJson] });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("package.json");
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

      expect(result).toEqual({ packageJsonContents: [mockPackageJson] });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("package.json");
      expect(mockZip.entryData).not.toHaveBeenCalledWith("node_modules/package.json");
    });

    it("skips package.json directory", async () => {
      mockZip.entries.mockResolvedValue({
        "package.json": { name: "package.json", isFile: false },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockZip.entryData).not.toHaveBeenCalled();
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
        packageJsonContents: [mockPackageJsons.root, mockPackageJsons.app],
      });
      expect(mockZip.entryData).toHaveBeenCalledTimes(2);
      expect(mockZip.entryData).toHaveBeenNthCalledWith(1, "package.json");
      expect(mockZip.entryData).toHaveBeenNthCalledWith(2, "packages/app/package.json");
    });
  });

  describe("when package.json not present", () => {
    beforeEach(() => {
      mockZip.entryData.mockResolvedValue(Buffer.from(mockBundle));
    });

    it("returns bundleContent for index.js file, if present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.js": { name: "index.js", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockBundle });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.js");
    });

    it("returns bundleContent for index.mjs file when index.js not present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.mjs": { name: "index.mjs", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockBundle });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.mjs");
    });

    it("returns bundleContent for index.cjs file when index.js/mjs not present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.cjs": { name: "index.cjs", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockBundle });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.cjs");
    });

    it("prefers index.js over index.mjs/cjs when all are present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.js": { name: "index.js", isFile: true },
        "index.mjs": { name: "index.mjs", isFile: true },
        "index.cjs": { name: "index.cjs", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockBundle });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.js");
    });

    it("prefers index.mjs over index.cjs when both are present", async () => {
      mockZip.entries.mockResolvedValue({
        "index.mjs": { name: "index.mjs", isFile: true },
        "index.cjs": { name: "index.cjs", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockBundle });
      expect(mockZip.entryData).toHaveBeenCalledOnce();
      expect(mockZip.entryData).toHaveBeenCalledWith("index.mjs");
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
    });

    it("returns empty object when no package.json or index.js/mjs/cjs", async () => {
      mockZip.entries.mockResolvedValue({
        "other.js": { name: "other.js", isFile: true },
      });

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockZip.entryData).not.toHaveBeenCalled();
    });
  });
});
