import { describe, it, expect, vi } from "vitest";
import { getLambdaFunctions } from "./getLambdaFunctions.ts";

vi.mock("@aws-sdk/client-lambda", () => ({
  paginateListFunctions: vi.fn(),
}));

import type { Paginator } from "@smithy/types";
import { type ListFunctionsCommandOutput, paginateListFunctions } from "@aws-sdk/client-lambda";

describe(getLambdaFunctions.name, () => {
  const mockClient = {} as any;

  it("returns empty array when no functions", async () => {
    vi.mocked(paginateListFunctions).mockReturnValue(
      (async function* () {
        yield { Functions: [] };
      })() as Paginator<ListFunctionsCommandOutput>,
    );

    const result = await getLambdaFunctions(mockClient);
    expect(result).toEqual([]);
  });

  it("filters only nodejs runtime functions", async () => {
    vi.mocked(paginateListFunctions).mockReturnValue(
      (async function* () {
        yield {
          Functions: [
            { FunctionName: "fn1", Runtime: "nodejs18.x" },
            { FunctionName: "fn2", Runtime: "python3.9" },
          ],
        };
        yield {
          Functions: [{ FunctionName: "fn3", Runtime: "nodejs20.x" }],
        };
      })() as Paginator<ListFunctionsCommandOutput>,
    );

    const result = await getLambdaFunctions(mockClient);
    expect(result).toEqual([
      { FunctionName: "fn1", Runtime: "nodejs18.x" },
      { FunctionName: "fn3", Runtime: "nodejs20.x" },
    ]);
  });

  it("handles undefined Functions in page", async () => {
    vi.mocked(paginateListFunctions).mockReturnValue(
      (async function* () {
        yield { Functions: undefined };
      })() as Paginator<ListFunctionsCommandOutput>,
    );

    const result = await getLambdaFunctions(mockClient);
    expect(result).toEqual([]);
  });

  it("handles undefined Runtime in Functions", async () => {
    vi.mocked(paginateListFunctions).mockReturnValue(
      (async function* () {
        yield { FunctionName: "fn1" };
      })() as Paginator<ListFunctionsCommandOutput>,
    );

    const result = await getLambdaFunctions(mockClient);
    expect(result).toEqual([]);
  });
});
