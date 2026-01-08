import { describe, it, expect } from "vitest";
import { getCodeSizeToDownload } from "./getCodeSizeToDownload.ts";

describe("getCodeSizeToDownload", () => {
  it("returns 0 for empty functions array", () => {
    expect(getCodeSizeToDownload([])).toBe(0);
  });

  it("sums function code sizes", () => {
    expect(getCodeSizeToDownload([{ CodeSize: 100 }, { CodeSize: 200 }])).toBe(300);
  });

  it("handles functions without CodeSize", () => {
    expect(getCodeSizeToDownload([{ FunctionName: "fn1" }, { CodeSize: 100 }])).toBe(100);
  });
});
