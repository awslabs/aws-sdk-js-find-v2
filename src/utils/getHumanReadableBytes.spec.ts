import { describe, it, expect } from "vitest";
import { getHumanReadableBytes } from "./getHumanReadableBytes";

describe("getHumanReadableBytes", () => {
  it("returns '0 Bytes' for 0", () => {
    expect(getHumanReadableBytes(0)).toBe("0 Bytes");
  });

  it.each([
    [1, "1 Bytes"],
    [1024, "1 KB"],
    [1024 ** 2, "1 MB"],
    [1024 ** 3, "1 GB"],
    [1024 ** 4, "1 TB"],
    [1024 ** 5, "1 PB"],
    [1536, "1.5 KB"],
  ])("returns '%s' for %i bytes", (bytes, expected) => {
    expect(getHumanReadableBytes(bytes)).toBe(expected);
  });

  it("respects custom decimals", () => {
    expect(getHumanReadableBytes(1536, 0)).toBe("2 KB");
    expect(getHumanReadableBytes(1536, 1)).toBe("1.5 KB");
  });
});
