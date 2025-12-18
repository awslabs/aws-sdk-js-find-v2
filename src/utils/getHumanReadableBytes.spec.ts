import { describe, it, expect } from "vitest";
import { getHumanReadableBytes } from "./getHumanReadableBytes";

describe("getHumanReadableBytes", () => {
  it.each([
    [-1, "0 Bytes"],
    [0, "0 Bytes"],
    [1, "1 Bytes"],
    [1024, "1 KB"],
    [1024 ** 2, "1 MB"],
    [1024 ** 3, "1 GB"],
    [1024 ** 4, "1 TB"],
    [1024 ** 5, "1 PB"],
    [1024 ** 6, "1024 PB"],
    [1536, "1.5 KB"],
  ])("converts %i bytes to '%s'", (bytes, expected) => {
    expect(getHumanReadableBytes(bytes)).toBe(expected);
  });

  it("respects custom decimals", () => {
    expect(getHumanReadableBytes(1536, 0)).toBe("2 KB");
    expect(getHumanReadableBytes(1536, 1)).toBe("1.5 KB");
  });
});
