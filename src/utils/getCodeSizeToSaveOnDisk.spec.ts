import type { FunctionConfiguration } from "@aws-sdk/client-lambda";
import { describe, expect, it } from "vitest";
import { getCodeSizeToSaveOnDisk } from "./getCodeSizeToSaveOnDisk.ts";

describe("getCodeSizeToSaveOnDisk", () => {
  it("returns 0 for empty functions array", () => {
    expect(getCodeSizeToSaveOnDisk([], 5)).toBe(0);
  });

  it("returns function code size without layers", () => {
    const functions: FunctionConfiguration[] = [{ CodeSize: 100 }, { CodeSize: 200 }];
    expect(getCodeSizeToSaveOnDisk(functions, 2)).toBe(300);
  });

  it("returns sum of function and layer sizes", () => {
    const functions: FunctionConfiguration[] = [
      { CodeSize: 100, Layers: [{ Arn: "layer1", CodeSize: 50 }] },
    ];
    expect(getCodeSizeToSaveOnDisk(functions, 1)).toBe(150);
  });

  it("deduplicates shared layers across functions", () => {
    const functions: FunctionConfiguration[] = [
      { CodeSize: 100, Layers: [{ Arn: "shared-layer", CodeSize: 50 }] },
      { CodeSize: 200, Layers: [{ Arn: "shared-layer", CodeSize: 50 }] },
    ];
    expect(getCodeSizeToSaveOnDisk(functions, 2)).toBe(350); // 100 + 200 + 50
  });

  it("selects largest functions by total size", () => {
    const functions: FunctionConfiguration[] = [
      { CodeSize: 50 },
      { CodeSize: 10, Layers: [{ Arn: "layer1", CodeSize: 200 }] },
      { CodeSize: 75 },
    ];
    expect(getCodeSizeToSaveOnDisk(functions, 1)).toBe(210); // 10 + 200
  });

  it("handles missing CodeSize and Layers", () => {
    const functions: FunctionConfiguration[] = [{ FunctionName: "test" }, { CodeSize: 100 }];
    expect(getCodeSizeToSaveOnDisk(functions, 2)).toBe(100);
  });
});
