import type { FunctionConfiguration } from "@aws-sdk/client-lambda";
import { getLambdaLayerToCodeSizeMap } from "./getLambdaLayerToCodeSizeMap.ts";

export const getCodeSizeToDownload = (functions: FunctionConfiguration[]) =>
  functions.reduce((acc, fn) => acc + (fn.CodeSize || 0), 0) +
  [...getLambdaLayerToCodeSizeMap(functions).values()].reduce((acc, size) => acc + size, 0);
