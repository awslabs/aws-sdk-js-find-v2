import type { FunctionConfiguration } from "@aws-sdk/client-lambda";

export const getCodeSizeToDownload = (functions: FunctionConfiguration[]) =>
  functions.reduce((acc, fn) => acc + (fn.CodeSize || 0), 0);
