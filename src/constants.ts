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
