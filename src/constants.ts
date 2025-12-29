export interface LambdaCommandOptions {
  // AWS region to scan
  region?: string;

  // answer yes for all prompts
  yes?: boolean;

  // number of jobs run at once; defaults to number of CPUs
  jobs?: number;
}
