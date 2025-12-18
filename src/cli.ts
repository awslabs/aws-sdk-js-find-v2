import { Command } from "commander";
import type { LambdaCommandOptions } from "./constants.ts";
import packageJson from "../package.json" with { type: "json" };
import { scanLambdaFunctions } from "./scanLambdaFunctions.ts";

/**
 * Creates and configures the CLI program with available commands.
 *
 * @returns The configured Commander program instance
 * @internal
 */
export const createProgram = (): Command => {
  const program = new Command();

  program
    .name(packageJson.name)
    .description("CLI to find resources which call AWS using JavaScript SDK v2")
    .version(packageJson.version, "-v, --version");

  program
    .command("lambda")
    .description("Scans Lambda Node.js Functions for JavaScript SDK v2")
    .option("-r, --region <region>", "AWS region to scan")
    .option("-y, --yes", "answer yes for all prompts")
    .action(async (options: LambdaCommandOptions) => {
      await scanLambdaFunctions(options);
    });
  return program;
};
