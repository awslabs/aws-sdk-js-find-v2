import { type Lambda, paginateListFunctions } from "@aws-sdk/client-lambda";

/**
 * Retrieves all Lambda functions with Node.js runtime from AWS
 *
 * @param client - AWS Lambda client instance
 * @param lambdaNodeJsMajorVersions - Array of Node.js major versions to filter (e.g., ["18", "20"])
 * @returns Promise that resolves to array of Lambda function configurations
 * @description
 * - Uses AWS SDK v3 pagination to handle large number of functions
 * - Filters results to only include specified Node.js runtimes
 * - Returns empty array if no functions found
 */
export const getLambdaFunctions = async (client: Lambda, lambdaNodeJsMajorVersions: string[]) => {
  const functions = [];
  const lambdaNodeJsIdentifiers = lambdaNodeJsMajorVersions.map((version) => `nodejs${version}.x`);

  const paginator = paginateListFunctions({ client }, {});
  for await (const page of paginator) {
    functions.push(
      ...(page.Functions ?? []).filter((fn) => lambdaNodeJsIdentifiers.includes(fn.Runtime ?? "")),
    );
  }

  return functions;
};
