import StreamZip from "node-stream-zip";

/**
 * Processes entries in a zip file using a callback function.
 *
 * @param zipPath - Path to the zip file.
 * @param processor - Callback to process each entry.
 */
export const processZipEntries = async (
  zipPath: string,
  processor: (entry: StreamZip.ZipEntry, getData: () => Promise<Buffer>) => Promise<void>,
) => {
  const zip = new StreamZip.async({ file: zipPath });

  // Continue with empty object, if zip entries can't be read.
  const zipEntries = await zip.entries().catch(() => ({}));

  for (const entry of Object.values(zipEntries)) {
    // Processor callback is provided by callee, and it should handle errors.
    await processor(entry, () => zip.entryData(entry.name)).catch(() => {});
  }

  await zip.close();
};
