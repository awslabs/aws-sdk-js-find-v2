import { type Lambda, paginateListFunctions } from "@aws-sdk/client-lambda";

export const getLambdaFunctions = async (client: Lambda) => {
  const functions = [];
  const paginator = paginateListFunctions({ client }, {});
  for await (const page of paginator) {
    functions.push(...(page.Functions ?? []).filter((fn) => fn.Runtime?.startsWith("nodejs")));
  }
  return functions;
};
