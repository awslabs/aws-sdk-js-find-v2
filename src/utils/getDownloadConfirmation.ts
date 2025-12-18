import { createInterface } from "node:readline/promises";
import { getHumanReadableBytes } from "./getHumanReadableBytes.ts";

/**
 * Prompts user for confirmation before downloading Lambda function code
 *
 * @param functionCount - Number of Lambda functions to be processed
 * @param codeSizeToDownload - Total size of all function code in bytes
 * @returns Promise that resolves to boolean indicating user's choice
 * @description
 * - Creates interactive readline interface for user input
 * - Displays summary of operations including function count and total size
 * - Returns true if user confirms with 'y' or 'yes', false otherwise
 */
export const getDownloadConfirmation = async (
  functionCount: number,
  codeSizeToDownload: number,
  codeSizeToSaveOnDisk: number,
): Promise<boolean> => {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const answer = await rl.question(
    `This command will process ${functionCount} Lambda Node.js functions, and` +
      `\ndownload ${getHumanReadableBytes(codeSizeToDownload)} of compressed archives over the network.` +
      `\nIt'll store maximum of ${getHumanReadableBytes(codeSizeToSaveOnDisk)} on disk at any point.` +
      `\n\nDo you want to continue? (y/N): `,
  );
  rl.close();

  return ["y", "yes"].includes(answer.trim().toLowerCase());
};
