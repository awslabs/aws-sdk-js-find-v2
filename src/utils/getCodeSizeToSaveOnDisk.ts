import type { FunctionConfiguration } from "@aws-sdk/client-lambda";

export const getCodeSizeToSaveOnDisk = (functions: FunctionConfiguration[], num: number) =>
  functions
    .map((fn) => fn.CodeSize || 0)
    .sort((a, b) => b - a)
    .slice(0, num)
    .reduce((acc, size) => acc + size, 0);
