import type { FunctionConfiguration } from "@aws-sdk/client-lambda";
import { getLambdaLayerToCodeSizeMap } from "./getLambdaLayerToCodeSizeMap.ts";

const getFunctionTotalSize = (fn: FunctionConfiguration) =>
  (fn.CodeSize || 0) + (fn.Layers?.reduce((acc, l) => acc + (l.CodeSize || 0), 0) || 0);

export const getCodeSizeToSaveOnDisk = (functions: FunctionConfiguration[], num: number) => {
  const largestFunctions = functions
    .sort((a, b) => getFunctionTotalSize(b) - getFunctionTotalSize(a))
    .slice(0, num);
  const functionSize = largestFunctions.reduce((acc, fn) => acc + (fn.CodeSize || 0), 0);
  const layerSize = [...getLambdaLayerToCodeSizeMap(largestFunctions).values()].reduce(
    (acc, size) => acc + size,
    0,
  );
  return functionSize + layerSize;
};
