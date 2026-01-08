import StreamZip from "node-stream-zip";

/**
 * Processes entries in a zip file using a callback function.
 *
 * @param zipPath - Path to the zip file.
 * @param processor - Callback to process each entry. Return undefined to skip.
 * @returns Array of non-undefined results from the processor.
 */
export const processZipEntries = async <T>(
  zipPath: string,
  processor: (entry: StreamZip.ZipEntry, getData: () => Promise<Buffer>) => Promise<T | undefined>,
): Promise<T[]> => {
  const zip = new StreamZip.async({ file: zipPath });
  const results: T[] = [];

  let zipEntries: Record<string, StreamZip.ZipEntry> = {};
  try {
    zipEntries = await zip.entries();
  } catch {
    // Continue with empty object, if zip entries can't be read.
  }

  for (const entry of Object.values(zipEntries)) {
    const result = await processor(entry, () => zip.entryData(entry.name));
    if (result !== undefined) results.push(result);
  }

  await zip.close();
  return results;
};
