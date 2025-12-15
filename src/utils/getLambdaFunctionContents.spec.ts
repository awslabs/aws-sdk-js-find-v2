import { describe, it, expect, vi } from "vitest";
import unzipper from "unzipper";
import { getLambdaFunctionContents } from "./getLambdaFunctionContents.ts";

vi.mock("unzipper");

describe(getLambdaFunctionContents.name, () => {
  const mockZipPath = "/path/to/file.zip";
  const mockPackageJson = '{"name":"test"}';
  const mockBundle = "bundle content";
  const mockMjsBundle = "mjs content";
  const mockCjsBundle = "cjs content";

  describe("when package.json present", () => {
    it("returns packageJsonContents from package.json", async () => {
      const mockFiles = [
        {
          type: "File",
          path: "package.json",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockPackageJson)),
        },
        {
          type: "File",
          path: "index.js",
          buffer: vi.fn(),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ packageJsonContents: [mockPackageJson] });
      expect(mockFiles[0].buffer).toHaveBeenCalled();
      expect(mockFiles[1].buffer).not.toHaveBeenCalled();
    });

    it("skips node_modules directory", async () => {
      const mockFiles = [
        {
          type: "File",
          path: "package.json",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockPackageJson)),
        },
        {
          type: "File",
          path: "node_modules/package.json",
          buffer: vi.fn(),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ packageJsonContents: [mockPackageJson] });
      expect(mockFiles[0].buffer).toHaveBeenCalled();
      expect(mockFiles[1].buffer).not.toHaveBeenCalled();
    });

    it("returns multiple package.json files", async () => {
      const mockFiles = [
        {
          type: "File",
          path: "package.json",
          buffer: vi.fn().mockResolvedValue(Buffer.from('{"name":"root"}')),
        },
        {
          type: "File",
          path: "packages/app/package.json",
          buffer: vi.fn().mockResolvedValue(Buffer.from('{"name":"app"}')),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({
        packageJsonContents: ['{"name":"root"}', '{"name":"app"}'],
      });
      expect(mockFiles[0].buffer).toHaveBeenCalled();
      expect(mockFiles[1].buffer).toHaveBeenCalled();
    });
  });

  describe("when package.json not present", () => {
    it("returns bundleContent for index.js file, if present", async () => {
      const mockFiles = [
        {
          type: "File",
          path: "index.js",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockBundle)),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockBundle });
      expect(mockFiles[0].buffer).toHaveBeenCalled();
    });

    it("returns bundleContent for index.mjs file when index.js not present", async () => {
      const mockFiles = [
        {
          type: "File",
          path: "index.mjs",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockMjsBundle)),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockMjsBundle });
      expect(mockFiles[0].buffer).toHaveBeenCalled();
    });

    it("returns bundleContent for index.cjs file when index.js/mjs not present", async () => {
      const mockFiles = [
        {
          type: "File",
          path: "index.cjs",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockCjsBundle)),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockCjsBundle });
      expect(mockFiles[0].buffer).toHaveBeenCalled();
    });

    it("prefers index.js over index.mjs/cjs when all are present", async () => {
      const mockFiles = [
        {
          type: "File",
          path: "index.cjs",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockCjsBundle)),
        },
        {
          type: "File",
          path: "index.mjs",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockMjsBundle)),
        },
        {
          type: "File",
          path: "index.js",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockBundle)),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockBundle });
      expect(mockFiles[2].buffer).toHaveBeenCalled();
      expect(mockFiles[1].buffer).not.toHaveBeenCalled();
      expect(mockFiles[0].buffer).not.toHaveBeenCalled();
    });

    it("prefers index.mjs over index.cjs when both are present", async () => {
      const mockFiles = [
        {
          type: "File",
          path: "index.cjs",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockCjsBundle)),
        },
        {
          type: "File",
          path: "index.mjs",
          buffer: vi.fn().mockResolvedValue(Buffer.from(mockMjsBundle)),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({ bundleContent: mockMjsBundle });
      expect(mockFiles[1].buffer).toHaveBeenCalled();
      expect(mockFiles[0].buffer).not.toHaveBeenCalled();
    });

    it("skips index.js/mjs/cjs if it's a directory", async () => {
      const mockFiles = [
        {
          type: "Directory",
          path: "index.js",
          buffer: vi.fn(),
        },
        {
          type: "Directory",
          path: "index.mjs",
          buffer: vi.fn(),
        },
        {
          type: "Directory",
          path: "index.cjs",
          buffer: vi.fn(),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockFiles[0].buffer).not.toHaveBeenCalled();
      expect(mockFiles[1].buffer).not.toHaveBeenCalled();
      expect(mockFiles[2].buffer).not.toHaveBeenCalled();
    });

    it("returns empty object when no package.json or index.js/mjs/cjs", async () => {
      const mockFiles = [
        {
          type: "File",
          path: "other.js",
          buffer: vi.fn(),
        },
      ];
      vi.mocked(unzipper.Open.file).mockResolvedValue({
        files: mockFiles,
      } as any);

      const result = await getLambdaFunctionContents(mockZipPath);

      expect(result).toEqual({});
      expect(mockFiles[0].buffer).not.toHaveBeenCalled();
    });
  });
});
