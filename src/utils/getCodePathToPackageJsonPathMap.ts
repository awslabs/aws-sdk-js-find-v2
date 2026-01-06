import { dirname, join } from "path";

import { PACKAGE_JSON } from "./constants.ts";

const ROOT_DIR = ".";

/**
 * Returns map with codepath as key and closest package.json path as value.
 * It starts in the codepath directory and searches up the parent directory chain until it finds one.
 *
 * @param codePaths - Set of code file paths to map.
 * @param packageJsonPaths - Set of package.json file paths.
 * @returns Map where keys are code paths and values are their closest package.json paths.
 */
export const getCodePathToPackageJsonPathMap = (
  codePaths: Set<string>,
  packageJsonPaths: Set<string>,
): Map<string, string> => {
  const codePathToPackageJsonPathMap = new Map();

  const dirToPackageJsonPathMap = new Map([
    [ROOT_DIR, packageJsonPaths.has(PACKAGE_JSON) ? PACKAGE_JSON : undefined],
  ]);

  const findPackageJson = (dir: string): string | undefined => {
    if (dirToPackageJsonPathMap.has(dir)) {
      return dirToPackageJsonPathMap.get(dir);
    }

    const candidate = join(dir, PACKAGE_JSON);
    const found = packageJsonPaths.has(candidate) ? candidate : findPackageJson(dirname(dir));

    dirToPackageJsonPathMap.set(dir, found);
    return found;
  };

  for (const codePath of codePaths) {
    const pkg = findPackageJson(dirname(codePath));
    if (pkg) codePathToPackageJsonPathMap.set(codePath, pkg);
  }

  return codePathToPackageJsonPathMap;
};
