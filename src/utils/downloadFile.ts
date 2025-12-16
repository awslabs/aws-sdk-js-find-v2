import { writeFile } from "node:fs/promises";

/**
 * Downloads a file from a URL and saves it to the specified path.
 *
 * @param url - The URL of the file to download.
 * @param outputPath - The local file path where the downloaded file should be saved.
 * @throws {Error} If the download fails or response body is null.
 * @returns Promise that resolves when file is downloaded and saved.
 */
export const downloadFile = async (url: string, outputPath: string) => {
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(
      `Failed to download '${url}'. Received ${response.status} with '${response.statusText}'.`,
    );
  }

  if (!response.body) {
    throw new Error(`Response body is null for '${url}'`);
  }

  await writeFile(outputPath, response.body);
};
