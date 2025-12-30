import { describe, it, expect } from "vitest";
import { getLambdaNodeJsMatchingVersions } from "./getLambdaNodeJsMatchingVersions";

describe("getLambdaNodeJsMatchingVersions", () => {
  it.each([
    [">=18", ["18", "20", "22", "24"]],
    ["<18", ["10", "12", "14", "16"]],
    [">=20 <24", ["20", "22"]],
    ["18", ["18"]],
    [">=99", []],
  ])("returns matching versions for '%s'", (semverRange, expected) => {
    expect(getLambdaNodeJsMatchingVersions(semverRange)).toEqual(expected);
  });
});
