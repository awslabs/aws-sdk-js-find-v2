import { beforeEach, describe, it, expect, vi } from "vitest";
import type { Lambda } from "@aws-sdk/client-lambda";
import { processRemoteZip } from "./processRemoteZip.ts";
import { processZipEntries } from "./processZipEntries.ts";
import { getLambdaLayerContents } from "./getLambdaLayerContents.ts";
import { getSdkVersionFromLambdaLayerContents } from "./getSdkVersionFromLambdaLayerContents.ts";

vi.mock("./processRemoteZip.ts");
vi.mock("./processZipEntries.ts");
vi.mock("./getLambdaLayerContents.ts");
vi.mock("./getSdkVersionFromLambdaLayerContents.ts");

describe("getLambdaFunctionContents", () => {
  const mockCodeLocation = "https://example.com/code.zip";
  const mockPackageJson = '{"name":"test"}';
  const mockCode = "code content";
  const mockClient = {
    getLayerVersionByArn: vi.fn(),
  } as unknown as Lambda;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    vi.mocked(processRemoteZip).mockImplementation(async (_url, processor) => {
      await processor("/tmp/test.zip");
    });
    vi.mocked(getLambdaLayerContents).mockResolvedValue(new Map());
    vi.mocked(getSdkVersionFromLambdaLayerContents).mockReturnValue(undefined);
  });

  it("returns empty codeMap when zip has no entries", async () => {
    const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
    vi.mocked(processZipEntries).mockResolvedValue();

    const result = await getLambdaFunctionContents(mockClient, {
      codeLocation: mockCodeLocation,
      runtime: "nodejs20.x",
      includePackageJson: false,
    });
    expect(result).toEqual({ codeMap: new Map() });
    expect(processRemoteZip).toHaveBeenCalledWith(mockCodeLocation, expect.any(Function));
  });

  describe("returns empty codeMap when entry data can't be read", () => {
    it("with only package.json", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.reject(new Error("zip entry data error")),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("with only index.js", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.reject(new Error("zip entry data error")),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("with both package.json and index.js", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.reject(new Error("zip entry data error")),
        );
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.reject(new Error("zip entry data error")),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map() });
    });
  });

  describe("when package.json present", () => {
    it("returns packageJsonMap", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: true,
      });
      expect(result).toEqual({
        codeMap: new Map([["index.js", mockCode]]),
        packageJsonMap: new Map([["package.json", mockPackageJson]]),
      });
    });

    it("skips node_modules directory", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
        await processor({ name: "node_modules/package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: true,
      });
      expect(result).toEqual({
        codeMap: new Map(),
        packageJsonMap: new Map([["package.json", mockPackageJson]]),
      });
    });

    it("skips package.json directory", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: false } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("skips package.json files when includePackageJson is false", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({
        codeMap: new Map([["index.js", mockCode]]),
      });
    });

    it("returns multiple package.json files", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
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

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: true,
      });
      expect(result).toEqual({
        codeMap: new Map(),
        packageJsonMap: new Map([
          ["package.json", mockPackageJsons.root],
          ["packages/app/package.json", mockPackageJsons.app],
        ]),
      });
    });

    it("populates awsSdkPackageJsonMap for aws-sdk package.json", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      const awsSdkPackageJson = '{"name":"aws-sdk","version":"2.1692.0"}';
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "node_modules/aws-sdk/package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(awsSdkPackageJson)),
        );
        await processor({ name: "package.json", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockPackageJson)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: true,
      });
      expect(result).toEqual({
        codeMap: new Map(),
        packageJsonMap: new Map([["package.json", mockPackageJson]]),
        awsSdkPackageJsonMap: new Map([["node_modules/aws-sdk/package.json", awsSdkPackageJson]]),
      });
    });

    it("populates awsSdkPackageJsonMap for nested aws-sdk package.json", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
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

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: true,
      });
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
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map([["index.js", mockCode]]) });
    });

    it("returns codeMap for .mjs files", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.mjs", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map([["index.mjs", mockCode]]) });
    });

    it("returns codeMap for .cjs files", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.cjs", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map([["index.cjs", mockCode]]) });
    });

    it("returns codeMap for .ts files", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.ts", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map([["index.ts", mockCode]]) });
    });

    it("returns codeMap with multiple code files", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.js", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
        await processor({ name: "utils.js", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({
        codeMap: new Map([
          ["index.js", mockCode],
          ["utils.js", mockCode],
        ]),
      });
    });

    it("skips non-file entries", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "index.js", isFile: false } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("skips non-code files", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockImplementation(async (_zipPath, processor) => {
        await processor({ name: "readme.md", isFile: true } as never, () =>
          Promise.resolve(Buffer.from(mockCode)),
        );
      });

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
      });
      expect(result).toEqual({ codeMap: new Map() });
    });
  });

  describe("layer processing", () => {
    it("processes layers and adds AWS SDK version to awsSdkPackageJsonMap", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      const mockLayerArn = "arn:aws:lambda:us-east-1:123456789012:layer:test-layer:1";
      const mockLayerContents = new Map([
        ["nodejs/node_modules/aws-sdk/package.json", '{"version":"2.1692.0"}'],
      ]);

      vi.mocked(mockClient.getLayerVersionByArn).mockResolvedValue({
        Content: { Location: "https://example.com/layer.zip" },
      });
      vi.mocked(getLambdaLayerContents).mockResolvedValue(mockLayerContents);
      vi.mocked(getSdkVersionFromLambdaLayerContents).mockReturnValue("2.1692.0");
      vi.mocked(processZipEntries).mockResolvedValue();

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: true,
        layers: [{ Arn: mockLayerArn }],
      });

      expect(mockClient.getLayerVersionByArn).toHaveBeenCalledWith({ Arn: mockLayerArn });
      expect(getLambdaLayerContents).toHaveBeenCalledWith("https://example.com/layer.zip");
      expect(getSdkVersionFromLambdaLayerContents).toHaveBeenCalledWith(
        mockLayerContents,
        "nodejs20.x",
      );
      expect(result.awsSdkPackageJsonMap).toEqual(
        new Map([["node_modules/aws-sdk/package.json", '{"version":"2.1692.0"}']]),
      );
    });

    it("skips layers without ARN", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      vi.mocked(processZipEntries).mockResolvedValue();

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
        layers: [{}],
      });

      expect(mockClient.getLayerVersionByArn).not.toHaveBeenCalled();
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("skips layer processing when includePackageJson is false", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      const mockLayerArn = "arn:aws:lambda:us-east-1:123456789012:layer:test-layer:1";
      vi.mocked(processZipEntries).mockResolvedValue();

      const result = await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: false,
        layers: [{ Arn: mockLayerArn }],
      });

      expect(mockClient.getLayerVersionByArn).not.toHaveBeenCalled();
      expect(getLambdaLayerContents).not.toHaveBeenCalled();
      expect(result).toEqual({ codeMap: new Map() });
    });

    it("uses cached layer contents on subsequent calls", async () => {
      const { getLambdaFunctionContents } = await import("./getLambdaFunctionContents.ts");
      const mockLayerArn = "arn:aws:lambda:us-east-1:123456789012:layer:test-layer:1";
      const mockLayerContents = new Map();

      vi.mocked(mockClient.getLayerVersionByArn).mockResolvedValue({
        Content: { Location: "https://example.com/layer.zip" },
      });
      vi.mocked(getLambdaLayerContents).mockResolvedValue(mockLayerContents);
      vi.mocked(processZipEntries).mockResolvedValue();

      // First call
      await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: true,
        layers: [{ Arn: mockLayerArn }],
      });

      // Second call
      await getLambdaFunctionContents(mockClient, {
        codeLocation: mockCodeLocation,
        runtime: "nodejs20.x",
        includePackageJson: true,
        layers: [{ Arn: mockLayerArn }],
      });

      expect(mockClient.getLayerVersionByArn).toHaveBeenCalledTimes(1);
      expect(getLambdaLayerContents).toHaveBeenCalledTimes(1);
    });
  });
});
