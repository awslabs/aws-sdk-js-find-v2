import unzipper from "unzipper";
const PACKAGE_JSON_FILENAME = "package.json";

export type LambdaFunctionContents = {
  /**
   * String contents of all package.json files from Lambda Function.
   */
  packageJsonContents?: string[];

  /**
   * String contents of the index.js bundle file, if present.
   */
  bundleContent?: string;
};

/**
 * Extracts the contents of a Lambda Function zip file.
 * Returns string contents of package.json files, if available.
 * Otherwise, returns the contents of bundle file.
 *
 * @param zipPath - The path to the zip file of Lambda Function.
 * @returns Promise<LambdaFunctionContents> - Resolves to an object containing the extracted contents.
 */
export const getLambdaFunctionContents = async (
  zipPath: string,
): Promise<LambdaFunctionContents> => {
  const directory = await unzipper.Open.file(zipPath);

  const packageJsonContents = [];
  for (const file of directory.files) {
    // Skip 'node_modules' directory, as it's not the customer source code.
    if (file.path.includes("node_modules/")) continue;

    // Skip anything which is not `package.json`
    if (!file.path.endsWith(PACKAGE_JSON_FILENAME)) continue;

    const packageJsonContent = await file.buffer();
    packageJsonContents.push(packageJsonContent.toString());
  }

  if (packageJsonContents.length !== 0) {
    return { packageJsonContents };
  }

  let indexFile;
  for (const path of ["index.js", "index.mjs", "index.cjs"]) {
    indexFile = directory.files.find((f) => f.path === path && f.type === "File");
    if (indexFile) break;
  }

  if (indexFile) {
    const bundleContent = await indexFile.buffer();
    return { bundleContent: bundleContent.toString() };
  }

  return {};
};
