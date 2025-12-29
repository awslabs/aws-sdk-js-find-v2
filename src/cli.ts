import { Command } from "commander";
import { cpus } from "node:os";

import packageJson from "../package.json" with { type: "json" };
import { scanLambdaFunctions, type ScanLambdaFunctionsOptions } from "./scanLambdaFunctions.ts";

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
    .option(
      "-j, --jobs <count>",
      "number of parallel jobs",
      (value) => {
        const trimmed = value.trim();
        if (!/^\d+$/.test(trimmed)) {
          throw new Error("jobs must be a positive integer");
        }
        const parsed = Number.parseInt(trimmed, 10);
        if (parsed < 1) {
          throw new Error("jobs must be a positive integer");
        }
        return parsed;
      },
      cpus().length,
    )
    .action(async (options: ScanLambdaFunctionsOptions) => {
      await scanLambdaFunctions(options);
    });
  return program;
};
