import { describe, it, expect } from "vitest";

import { getCodePathToPackageJsonPathMap } from "./getCodePathToPackageJsonPathMap";

describe("getCodePathToPackageJsonPathMap", () => {
  it("maps code path to root package.json", () => {
    const codePaths = new Set(["index.js"]);
    const packageJsonPaths = new Set(["package.json"]);
    expect(getCodePathToPackageJsonPathMap(codePaths, packageJsonPaths)).toEqual(
      new Map([["index.js", "package.json"]]),
    );
  });

  it("maps code path to nested package.json", () => {
    const codePaths = new Set(["src/index.js"]);
    const packageJsonPaths = new Set(["src/package.json"]);
    expect(getCodePathToPackageJsonPathMap(codePaths, packageJsonPaths)).toEqual(
      new Map([["src/index.js", "src/package.json"]]),
    );
  });

  it("maps code path to closest package.json in parent chain", () => {
    const codePaths = new Set(["src/utils/helper.js"]);
    const packageJsonPaths = new Set(["package.json", "src/package.json"]);
    expect(getCodePathToPackageJsonPathMap(codePaths, packageJsonPaths)).toEqual(
      new Map([["src/utils/helper.js", "src/package.json"]]),
    );
  });

  it("excludes code paths without package.json", () => {
    const codePaths = new Set(["src/index.js"]);
    const packageJsonPaths = new Set(["other/package.json"]);
    expect(getCodePathToPackageJsonPathMap(codePaths, packageJsonPaths)).toEqual(new Map());
  });

  it("handles multiple code paths", () => {
    const codePaths = new Set(["index.js", "src/index.js", "lib/utils.js"]);
    const packageJsonPaths = new Set(["package.json", "src/package.json"]);
    expect(getCodePathToPackageJsonPathMap(codePaths, packageJsonPaths)).toEqual(
      new Map([
        ["index.js", "package.json"],
        ["src/index.js", "src/package.json"],
        ["lib/utils.js", "package.json"],
      ]),
    );
  });
});
