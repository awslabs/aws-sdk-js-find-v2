import { describe, it, expect } from "vitest";
import { getLambdaLayerToCodeSizeMap } from "./getLambdaLayerToCodeSizeMap.ts";

describe("getLambdaLayerToCodeSizeMap", () => {
  it("returns empty map for empty functions array", () => {
    expect(getLambdaLayerToCodeSizeMap([])).toEqual(new Map());
  });

  it("returns empty map when functions have no layers", () => {
    expect(getLambdaLayerToCodeSizeMap([{ FunctionName: "fn1" }])).toEqual(new Map());
  });

  it("extracts layer arn and code size from functions", () => {
    const result = getLambdaLayerToCodeSizeMap([
      { Layers: [{ Arn: "arn:layer1", CodeSize: 100 }] },
      { Layers: [{ Arn: "arn:layer2", CodeSize: 200 }] },
    ]);
    expect(result).toEqual(
      new Map([
        ["arn:layer1", 100],
        ["arn:layer2", 200],
      ]),
    );
  });

  it("filters out layers without Arn or CodeSize", () => {
    const result = getLambdaLayerToCodeSizeMap([
      { Layers: [{ Arn: "arn:layer1" }, { CodeSize: 100 }, { Arn: "arn:layer2", CodeSize: 200 }] },
    ]);
    expect(result).toEqual(new Map([["arn:layer2", 200]]));
  });

  it("doesn't count same layer twice", () => {
    const result = getLambdaLayerToCodeSizeMap([
      { Layers: [{ Arn: "arn:layer1", CodeSize: 100 }] },
      { Layers: [{ Arn: "arn:layer1", CodeSize: 100 }] },
    ]);
    expect(result).toEqual(new Map([["arn:layer1", 100]]));
  });
});
