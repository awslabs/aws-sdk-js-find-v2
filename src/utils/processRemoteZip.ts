import { randomUUID } from "node:crypto";
import { rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Downloads a zip file, runs a processor, then cleans up.
 *
 * @param url - The URL to download the zip from.
 * @param processor - Function that processes the zip file at the given path.
 */
export const processRemoteZip = async (
  url: string,
  processor: (zipPath: string) => Promise<void>,
) => {
  const zipPath = join(tmpdir(), `${randomUUID()}.zip`);
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(
      `Failed to download '${url}'. Received ${response.status} with '${response.statusText}'.`,
    );
  }

  if (!response.body) {
    throw new Error(`Response body is null for '${url}'`);
  }

  await writeFile(zipPath, response.body);

  try {
    await processor(zipPath);
  } finally {
    await rm(zipPath, { force: true });
  }
};
