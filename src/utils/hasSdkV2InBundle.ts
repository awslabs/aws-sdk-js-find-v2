import { satisfies } from "compare-versions";

const AWS_SDK_ENV_VARS = [
  "AWS_CONFIG_FILE",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CSM_CLIENT_ID", // v3 doesn't support CSM.
  "AWS_CSM_ENABLED", // v3 doesn't support CSM.
  "AWS_CSM_HOST", // v3 doesn't support CSM.
  "AWS_CSM_PORT", // v3 doesn't support CSM.
  "AWS_EC2_METADATA_DISABLED",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
  // "AWS_EC2_METADATA_V1_DISABLED", // Added in Nov'23 https://github.com/aws/aws-sdk-js/pull/4517
  "AWS_ENABLE_ENDPOINT_DISCOVERY",
  "AWS_ENDPOINT_DISCOVERY_ENABLED",
  "AWS_EXECUTION_ENV",
  // "AWS_LAMBDA_FUNCTION_NAME", // Added in May'22 https://github.com/aws/aws-sdk-js/pull/4111
  "AWS_NODEJS_CONNECTION_REUSE_ENABLED", // v3 enabled connection reuse by default.
  "AWS_PROFILE",
  "AWS_REGION",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_SDK_LOAD_CONFIG", // The v3 loads config by default. Specific to v2.
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_STS_REGIONAL_ENDPOINTS",
  // "AWS_USE_DUALSTACK_ENDPOINT", // Added in Nov'21 https://github.com/aws/aws-sdk-js/pull/3957
  // "AWS_USE_FIPS_ENDPOINT", // Added in Nov'21 https://github.com/aws/aws-sdk-js/pull/3951
  "AWS_WEB_IDENTITY_TOKEN_FILE",
];

/**
 * Checks if AWS SDK v2 is present in the provided bundle content by looking for specific environment variables.
 *
 * @param bundleContent - The string content of the bundle to check.
 * @param sdkVersionRange - Semver range string to check for AWS SDK for JavaScript v2
 * @returns boolean - Returns true if all AWS SDK v2 environment variables are found in the bundle content, false otherwise.
 */
export const hasSdkV2InBundle = (bundleContent: string, sdkVersionRange: string): boolean => {
  for (const envVar of AWS_SDK_ENV_VARS) {
    if (!bundleContent.includes(envVar)) {
      return false;
    }
  }

  // Get version number from `VERSION:'2.X.Y'` or `VERSION: '2.X.Y'`, including double quotes and backticks.
  const matches = bundleContent.match(/VERSION:\s*(['"`])(2\.\d+\.\d+)\1/);
  if (matches && matches[2]) {
    const version = matches[2];
    // If version is in the specified range, return true
    if (satisfies(version, sdkVersionRange)) {
      return true;
    }
  }

  return false;
};
