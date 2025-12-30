import { satisfies } from "compare-versions";

// Refs: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
export const LambdaNodeJsMajorVersions = ["10", "12", "14", "16", "18", "20", "22", "24"];

export const getLambdaNodeJsMajorVersions = (semverRange: string): string[] => {
  const identifiers = [];
  for (const nodejsVersion of LambdaNodeJsMajorVersions) {
    if (satisfies(nodejsVersion, semverRange)) {
      identifiers.push(nodejsVersion);
    }
  }
  return identifiers;
};
