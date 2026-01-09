import { join } from "node:path";
import { defineConfig } from "rolldown";

import { ModuleSystem, Version } from "./utils/constants.js";
import { getOutputDir } from "./utils/getOutputDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const createConfig = (version, minify, moduleSystem) =>
  defineConfig({
    input: getInputPath(version),
    output: {
      file: join(getOutputDir(version), getOutputFilename("rolldown", minify, moduleSystem)),
      format: moduleSystem,
      inlineDynamicImports: true,
      minify,
    },
    // rolldown defaults to "browser" platform for non-cjs formats: https://rolldown.rs/options/platform#platform
    platform: "node",
  });

const configs = [];
for (const version of Object.values(Version)) {
  for (const minify of [true, false]) {
    for (const moduleSystem of Object.values(ModuleSystem)) {
      configs.push(createConfig(version, minify, moduleSystem));
    }
  }
}

export default configs;
