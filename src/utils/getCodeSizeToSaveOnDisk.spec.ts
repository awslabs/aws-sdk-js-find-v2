import type { FunctionConfiguration } from "@aws-sdk/client-lambda";
import { describe, expect, it } from "vitest";
import { getCodeSizeToSaveOnDisk } from "./getCodeSizeToSaveOnDisk.ts";

describe("getCodeSizeToSaveOnDisk", () => {
  it("returns 0 for empty functions array", () => {
    expect(getCodeSizeToSaveOnDisk([], 5)).toBe(0);
  });

  it("returns code size for largest functions", () => {
    const functions: FunctionConfiguration[] = [
      { CodeSize: 10 },
      { CodeSize: 200 },
      { CodeSize: 100 },
    ];
    expect(getCodeSizeToSaveOnDisk(functions, 2)).toBe(300);
  });

  it("handles missing CodeSize", () => {
    const functions: FunctionConfiguration[] = [{ FunctionName: "test" }, { CodeSize: 100 }];
    expect(getCodeSizeToSaveOnDisk(functions, 2)).toBe(100);
  });
});
