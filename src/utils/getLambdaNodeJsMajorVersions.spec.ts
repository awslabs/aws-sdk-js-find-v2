import { describe, it, expect } from "vitest";
import { getLambdaNodeJsMajorVersions } from "./getLambdaNodeJsMajorVersions";

describe("getLambdaNodeJsMajorVersions", () => {
  it.each([
    [">=18", ["18", "20", "22", "24"]],
    ["<18", ["10", "12", "14", "16"]],
    [">=20 <24", ["20", "22"]],
    ["18", ["18"]],
    [">=99", []],
  ])("returns matching versions for '%s'", (semverRange, expected) => {
    expect(getLambdaNodeJsMajorVersions(semverRange)).toEqual(expected);
  });
});
