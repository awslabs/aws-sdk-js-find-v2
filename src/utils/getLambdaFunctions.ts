import { type Lambda, paginateListFunctions } from "@aws-sdk/client-lambda";

/**
 * Retrieves all Lambda functions with Node.js runtime from AWS
 *
 * @param client - AWS Lambda client instance
 * @returns Promise that resolves to array of Lambda function configurations
 * @description
 * - Uses AWS SDK v3 pagination to handle large number of functions
 * - Filters results to only include Node.js runtimes
 * - Returns empty array if no functions found
 */
export const getLambdaFunctions = async (client: Lambda) => {
  const functions = [];
  const paginator = paginateListFunctions({ client }, {});
  for await (const page of paginator) {
    functions.push(...(page.Functions ?? []).filter((fn) => fn.Runtime?.startsWith("nodejs")));
  }
  return functions;
};
