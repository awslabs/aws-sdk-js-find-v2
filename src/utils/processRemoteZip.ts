import { randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";

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

  // Stream the response to disk instead of loading into memory
  const writeStream = createWriteStream(zipPath);
  await pipeline(Readable.fromWeb(response.body as ReadableStream), writeStream);

  try {
    await processor(zipPath);
  } finally {
    await rm(zipPath, { force: true });
  }
};
