import { describe, it, expect } from "vitest";
import { getSdkVersionFromLambdaLayerContents } from "./getSdkVersionFromLambdaLayerContents";
import { AWS_SDK_PACKAGE_JSON } from "./constants";

describe("getSdkVersionFromLambdaLayerContents", () => {
  const runtime = "nodejs20.x";

  it("returns nodejs/node{major}/node_modules path first", () => {
    const contents = new Map([
      [`nodejs/node20/${AWS_SDK_PACKAGE_JSON}`, { version: "v1" }],
      [`nodejs/${AWS_SDK_PACKAGE_JSON}`, { version: "v2" }],
      [AWS_SDK_PACKAGE_JSON, { version: "v3" }],
    ]);
    expect(getSdkVersionFromLambdaLayerContents(contents, runtime)).toBe("v1");
  });

  it("returns nodejs/node_modules path second", () => {
    const contents = new Map([
      [`nodejs/${AWS_SDK_PACKAGE_JSON}`, { version: "v2" }],
      [AWS_SDK_PACKAGE_JSON, { version: "v3" }],
    ]);
    expect(getSdkVersionFromLambdaLayerContents(contents, runtime)).toBe("v2");
  });

  it("returns node_modules path third", () => {
    const contents = new Map([[AWS_SDK_PACKAGE_JSON, { version: "v3" }]]);
    expect(getSdkVersionFromLambdaLayerContents(contents, runtime)).toBe("v3");
  });

  it("returns undefined when no match", () => {
    expect(getSdkVersionFromLambdaLayerContents(new Map(), runtime)).toBeUndefined();
  });
});
