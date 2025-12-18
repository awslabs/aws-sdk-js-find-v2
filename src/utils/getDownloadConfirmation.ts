import { createInterface } from "node:readline/promises";
import { getHumanReadableBytes } from "./getHumanReadableBytes.ts";

export const getDownloadConfirmation = async (
  functionsLength: number,
  totalCodeSize: number,
): Promise<boolean> => {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const answer = await rl.question(
    `This script will process ${functionsLength} Lambda Node.js functions,` +
      `\nand download ${getHumanReadableBytes(totalCodeSize)} of compressed archives over the network.` +
      `\nDo you want to continue? (y/N): `,
  );
  rl.close();

  return ["y", "yes"].includes(answer.toLowerCase());
};
