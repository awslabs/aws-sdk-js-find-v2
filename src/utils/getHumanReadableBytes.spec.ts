import { describe, it, expect } from "vitest";
import { getHumanReadableBytes } from "./getHumanReadableBytes";

describe("getHumanReadableBytes", () => {
  it.each([
    [-1, "0 Bytes"],
    [0, "0 Bytes"],
    [1, "1 Bytes"],
    [1000, "1 KB"],
    [1000 ** 2, "1 MB"],
    [1000 ** 3, "1 GB"],
    [1000 ** 4, "1 TB"],
    [1000 ** 5, "1 PB"],
    [1000 ** 6, "1000 PB"],
    [1500, "1.5 KB"],
  ])("converts %i bytes to '%s'", (bytes, expected) => {
    expect(getHumanReadableBytes(bytes)).toBe(expected);
  });

  it("respects custom decimals", () => {
    expect(getHumanReadableBytes(1500, 0)).toBe("2 KB");
    expect(getHumanReadableBytes(1500, 1)).toBe("1.5 KB");
  });
});
