import type { FunctionConfiguration } from "@aws-sdk/client-lambda";

export const getLambdaLayerToCodeSizeMap = (
  functions: FunctionConfiguration[],
): Map<string, number> =>
  new Map(
    functions
      .flatMap((fn) => fn.Layers ?? [])
      .filter((layer) => layer.Arn && layer.CodeSize)
      .map((layer) => [layer.Arn!, layer.CodeSize!]),
  );
