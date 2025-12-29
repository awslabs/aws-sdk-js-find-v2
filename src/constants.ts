export const JS_SDK_V2_MARKER = {
  Y: "[Y]",
  N: "[N]",
  UNKNOWN: "[?]",
};

export interface LambdaCommandOptions {
  // AWS region to scan
  region?: string;

  // answer yes for all prompts
  yes?: boolean;

  // number of jobs run at once; defaults to number of CPUs
  jobs?: number;
}

export interface LambdaFunctionScanOutput {
  // The name of the Lambda function
  FunctionName: string;

  // Whether the Lambda function contains AWS SDK for JavaScript v2
  ContainsAwsSdkJsV2: boolean;

  // AWS region the Lambda function is deployed to
  Region: string;

  // The location of AWS SDK for JavaScript v2 in the Lambda function, if present.
  AwsSdkJsV2Location?: string;

  // The error message if there was an error scanning the Lambda function.
  AwsSdkJsV2Error?: string;
}
