import { describe, it, expect } from "vitest";

import { getCodePathToSdkVersionMap } from "./getCodePathToSdkVersionMap.ts";

describe("getCodePathToSdkVersionMap", () => {
  it("returns undefined for all codePaths when packageJsonMap is undefined", () => {
    const result = getCodePathToSdkVersionMap(["src/index.js"]);
    expect(result.get("src/index.js")).toBeUndefined();
  });

  it("returns undefined for all codePaths when packageJsonMap is empty", () => {
    const result = getCodePathToSdkVersionMap(["src/index.js"], new Map());
    expect(result.get("src/index.js")).toBeUndefined();
  });

  it("returns version from node_modules aws-sdk package.json", () => {
    const packageJsonMap = new Map([["package.json", "{}"]]);
    const awsSdkPackageJsonMap = new Map([
      ["node_modules/aws-sdk/package.json", '{"version":"2.1.0"}'],
    ]);
    const result = getCodePathToSdkVersionMap(["index.js"], packageJsonMap, awsSdkPackageJsonMap);
    expect(result.get("index.js")).toBe("2.1.0");
  });

  it("returns version from package.json dependencies when node_modules aws-sdk package.json is not present", () => {
    const packageJsonMap = new Map([["package.json", '{"dependencies":{"aws-sdk":"^2.0.0"}}']]);
    const result = getCodePathToSdkVersionMap(["index.js"], packageJsonMap);
    expect(result.get("index.js")).toBe("^2.0.0");
  });

  it("prefers node_modules aws-sdk version over that from package.json dependencies", () => {
    const packageJsonMap = new Map([["package.json", '{"dependencies":{"aws-sdk":"^2.0.0"}}']]);
    const awsSdkPackageJsonMap = new Map([
      ["node_modules/aws-sdk/package.json", '{"version":"2.1.0"}'],
    ]);
    const result = getCodePathToSdkVersionMap(["index.js"], packageJsonMap, awsSdkPackageJsonMap);
    expect(result.get("index.js")).toBe("2.1.0");
  });

  it("returns version from nested package.json", () => {
    const packageJsonMap = new Map([
      ["package.json", '{"dependencies":{"aws-sdk":"^2.0.0"}}'],
      ["src/package.json", '{"dependencies":{"aws-sdk":"^2.2.0"}}'],
    ]);
    const result = getCodePathToSdkVersionMap(["src/index.js"], packageJsonMap);
    expect(result.get("src/index.js")).toBe("^2.2.0");
  });

  it("traverses parent directories to find package.json", () => {
    const packageJsonMap = new Map([["package.json", '{"dependencies":{"aws-sdk":"^2.3.0"}}']]);
    const result = getCodePathToSdkVersionMap(["src/index.js"], packageJsonMap);
    expect(result.get("src/index.js")).toBe("^2.3.0");
  });

  it("handles invalid JSON gracefully", () => {
    const packageJsonMap = new Map([["package.json", "invalid json"]]);
    const result = getCodePathToSdkVersionMap(["index.js"], packageJsonMap);
    expect(result.get("index.js")).toBeUndefined();
  });
});
