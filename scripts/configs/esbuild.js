import { join } from "node:path";

import { build } from "esbuild";

import { ModuleSystem, Version } from "./utils/constants.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputDir } from "./utils/getOutputDir.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const promises = [];
for (const version of Object.values(Version)) {
  for (const minify of [true, false]) {
    for (const moduleSystem of Object.values(ModuleSystem)) {
      promises.push(
        build({
          bundle: true,
          minify,
          entryPoints: [getInputPath(version)],
          outfile: join(getOutputDir(version), getOutputFilename("esbuild", minify, moduleSystem)),
          format: moduleSystem,
          // esbuild defaults to "browser" platform https://esbuild.github.io/api/#platform
          platform: "node",
        }),
      );
    }
  }
}

await Promise.all(promises);
