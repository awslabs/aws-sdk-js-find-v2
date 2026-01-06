import { describe, it, expect } from "vitest";
import { getPossibleHandlerFiles } from "./getPossibleHandlerFiles";

describe("getPossibleHandlerFiles", () => {
  it.each([
    ["index.handler", ["index.js", "index.mjs", "index.cjs", "index.ts"]],
    ["src/app.handler", ["src/app.js", "src/app.mjs", "src/app.cjs", "src/app.ts"]],
    ["lambda", ["lambda.js", "lambda.mjs", "lambda.cjs", "lambda.ts"]],
  ])("returns possible files for '%s'", (handlerPath, expected) => {
    expect(getPossibleHandlerFiles(handlerPath)).toEqual(expected);
  });
});
