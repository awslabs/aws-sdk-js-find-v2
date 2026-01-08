import { beforeEach, describe, it, expect, vi } from "vitest";
import { getLambdaFunctionContents } from "./getLambdaFunctionContents.ts";
import { processRemoteZip } from "./processRemoteZip.ts";
import { processZipEntries } from "./processZipEntries.ts";

vi.mock("./processRemoteZip.ts");
vi.mock("./processZipEntries.ts");

describe("getLambdaFunctionContents", () => {
  const mockFunctionName = "test-function";
  const mockCodeLocation = "https://example.com/code.zip";
  const mockPackageJson = '{"name":"test"}';
  const mockCode = "code content";

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(processRemoteZip).mockImplementation(async (_url, _name, processor) => {
      await processor("/tmp/test.zip");
    });
  });

  it("returns empty codeMap when zip has no entries", async () => {
    vi.mocked(processZipEntries).mockResolvedValue();

    const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
    expect(result).toEqual({ codeMap: new Map() });
    expect(processRemoteZip).toHaveBeenCalledWith(
      mockCodeLocation,
      `function-${mockFunctionName}`,
      expect.any(Function),
    );
  });

  describe("returns empty codeMap when entry data can't be read", () => {
    it("with only package.json", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.reject(new Error("zip entry data error")),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("with only index.js", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.reject(new Error("zip entry data error")),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("with both package.json and index.js", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.reject(new Error("zip entry data error")),
        );
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.reject(new Error("zip entry data error")),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map() });
    });
  });

  describe("when package.json present", () => {
    it("returns packageJsonMap", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({
        codeMap: new Map([["index.js", mockCode]]),
        packageJsonMap: new Map([["package.json", mockPackageJson]]),
      });
    });

    it("skips node_modules directory", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
        await processor({ name: "node_modules/package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({
        codeMap: new Map(),
        packageJsonMap: new Map([["package.json", mockPackageJson]]),
      });
    });

    it("skips package.json directory", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: false } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("returns multiple package.json files", async () => {
      const mockPackageJsons = {
        root: '{"name":"root"}',
        app: '{"name":"app"}',
      };
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJsons.root)),
        );
        await processor({ name: "packages/app/package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJsons.app)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({
        codeMap: new Map(),
        packageJsonMap: new Map([
          ["package.json", mockPackageJsons.root],
          ["packages/app/package.json", mockPackageJsons.app],
        ]),
      });
    });

    it("populates awsSdkPackageJsonMap for aws-sdk package.json", async () => {
      const awsSdkPackageJson = '{"name":"aws-sdk","version":"2.1692.0"}';
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "node_modules/aws-sdk/package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(awsSdkPackageJson)),
        );
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({
        codeMap: new Map(),
        packageJsonMap: new Map([["package.json", mockPackageJson]]),
        awsSdkPackageJsonMap: new Map([["node_modules/aws-sdk/package.json", awsSdkPackageJson]]),
      });
    });

    it("populates awsSdkPackageJsonMap for nested aws-sdk package.json", async () => {
      const awsSdkPackageJson = '{"name":"aws-sdk","version":"2.1692.0"}';
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor(
          { name: "packages/app/node_modules/aws-sdk/package.json", isFile: true } as never,
          () => Promise.resolve(Buffer.from(awsSdkPackageJson)),
        );
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({
        codeMap: new Map(),
        packageJsonMap: new Map([["package.json", mockPackageJson]]),
        awsSdkPackageJsonMap: new Map([
          ["packages/app/node_modules/aws-sdk/package.json", awsSdkPackageJson],
        ]),
      });
    });
  });

  describe("code files", () => {
    it("returns codeMap for .js files", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map([["index.js", mockCode]]) });
    });

    it("returns codeMap for .mjs files", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.mjs", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map([["index.mjs", mockCode]]) });
    });

    it("returns codeMap for .cjs files", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.cjs", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map([["index.cjs", mockCode]]) });
    });

    it("returns codeMap for .ts files", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.ts", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map([["index.ts", mockCode]]) });
    });

    it("returns codeMap with multiple code files", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
        await processor({ name: "utils.js", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({
        codeMap: new Map([
          ["index.js", mockCode],
          ["utils.js", mockCode],
        ]),
      });
    });

    it("skips non-file entries", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.js", isFile: false } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("skips non-code files", async () => {
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "readme.md", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockFunctionName, mockCodeLocation);
      expect(result).toEqual({ codeMap: new Map() });
    });
  });
});
