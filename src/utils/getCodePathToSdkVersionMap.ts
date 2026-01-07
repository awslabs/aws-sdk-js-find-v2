import { dirname, join } from "node:path";

import { AWS_SDK, NODE_MODULES, PACKAGE_JSON } from "./constants.ts";

const AWS_SDK_PACKAGE_JSON = join(NODE_MODULES, AWS_SDK, PACKAGE_JSON);

const safeParse = (json: string) => {
  try {
    return JSON.parse(json);
  } catch {
    // ToDo: add warning when logging is supported in future.
    return {};
  }
};

/**
 * Maps code file paths to their JS SDK v2 versions.
 *
 * Searches up the directory tree from each code path to find package.json,
 * then resolves SDK version from node_modules/aws-sdk or dependencies.
 *
 * @param codePaths - Code file paths to map.
 * @param packageJsonMap - Map of package.json paths to contents.
 * @param awsSdkPackageJsonMap - Map of aws-sdk package.json paths to contents.
 * @returns Map of code paths to SDK versions (undefined if not found).
 */
export const getCodePathToSdkVersionMap = (
  codePaths: string[],
  packageJsonMap = new Map<string, string>(),
  awsSdkPackageJsonMap = new Map<string, string>(),
): Map<string, string | undefined> => {
  const dirToSdkVersionMap = new Map<string, string | undefined>();

  const getSdkVersion = (dir: string): string | undefined => {
    if (dirToSdkVersionMap.has(dir)) return dirToSdkVersionMap.get(dir);

    let version: string | undefined;

    // Assign version from node_modules aws-sdk package.json, if available.
    const awsSdkPackageJson =
      awsSdkPackageJsonMap.get(join(dir, AWS_SDK_PACKAGE_JSON)) ??
      awsSdkPackageJsonMap.get(AWS_SDK_PACKAGE_JSON);
    version ??= awsSdkPackageJson && safeParse(awsSdkPackageJson).version;

    // Assign version from package.json dependencies, if not populated yet.
    const pkgJson = packageJsonMap.get(join(dir, PACKAGE_JSON));
    version ??= pkgJson && safeParse(pkgJson).dependencies?.[AWS_SDK];

    // Assign undefined if it's rootDir, else call getSdkVersion on parent dir, if not populated yet.
    const parentDir = dirname(dir);
    version ??= parentDir !== dir ? getSdkVersion(parentDir) : undefined;

    dirToSdkVersionMap.set(dir, version);
    return version;
  };

  return new Map(codePaths.map((codePath) => [codePath, getSdkVersion(dirname(codePath))]));
};
