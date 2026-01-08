import { build } from "esbuild";
import { join } from "node:path";

import { ModuleSystem, Version } from "./utils/constants.js";
import { getOutputDir } from "./utils/getOutputDir.js";
import { getInputPath } from "./utils/getInputPath.js";
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
          platform: "node",
        }),
      );
    }
  }
}

await Promise.all(promises);
