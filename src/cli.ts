import { Command } from "commander";
import packageJson from "../package.json" with { type: "json" };
import { scanLambdaFunctions } from "./scanLambdaFunctions.ts";

export const createProgram = (): Command => {
  const program = new Command();

  program
    .name(packageJson.name)
    .description("CLI to find resources which call AWS using JavaScript SDK v2")
    .version(packageJson.version, "-v, --version");

  program
    .command("lambda")
    .description("Scans Lambda Node.js Functions for JavaScript SDK v2.")
    .action(async () => {
      await scanLambdaFunctions();
    });
  return program;
};
