import { createInterface } from "node:readline/promises";
import { getHumanReadableBytes } from "./getHumanReadableBytes.ts";

/**
 * Prompts user for confirmation before downloading Lambda function code
 *
 * @param functionCount - Number of Lambda functions to be processed
 * @param totalCodeSize - Total size of all function code in bytes
 * @returns Promise that resolves to boolean indicating user's choice
 * @description
 * - Creates interactive readline interface for user input
 * - Displays summary of operations including function count and total size
 * - Returns true if user confirms with 'y' or 'yes', false otherwise
 */
export const getDownloadConfirmation = async (
  functionCount: number,
  totalCodeSize: number,
): Promise<boolean> => {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const answer = await rl.question(
    `This script will process ${functionCount} Lambda Node.js functions,` +
      `\nand download ${getHumanReadableBytes(totalCodeSize)} of compressed archives over the network.` +
      `\nDo you want to continue? (y/N): `,
  );
  rl.close();

  return ["y", "yes"].includes(answer.trim().toLowerCase());
};
