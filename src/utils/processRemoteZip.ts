import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { downloadFile } from "./downloadFile.ts";

/**
 * Downloads a zip file, runs a processor, then cleans up.
 *
 * @param url - The URL to download the zip from.
 * @param name - Name for the temp file (sanitized automatically).
 * @param processor - Function that receives the zip path and returns a result.
 * @returns The result from the processor.
 */
export const processRemoteZip = async <T>(
  url: string,
  name: string,
  processor: (zipPath: string) => Promise<T>,
): Promise<T> => {
  const zipPath = join(tmpdir(), `${name.replace(/[/:]/g, "-")}.zip`);
  await downloadFile(url, zipPath);
  try {
    return await processor(zipPath);
  } finally {
    await rm(zipPath, { force: true });
  }
};
